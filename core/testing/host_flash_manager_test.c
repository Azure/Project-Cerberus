// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "rsa_testing.h"
#include "host_fw/host_flash_manager.h"
#include "host_fw/host_state_manager.h"
#include "flash/flash_common.h"
#include "mock/flash_master_mock.h"
#include "mock/spi_filter_interface_mock.h"
#include "mock/flash_mfg_filter_handler_mock.h"
#include "mock/host_control_mock.h"
#include "mock/pfm_mock.h"
#include "mock/pfm_manager_mock.h"
#include "engines/hash_testing_engine.h"
#include "engines/rsa_testing_engine.h"
#include "testing/spi_flash_sfdp_testing.h"
#include "testing/spi_flash_testing.h"


static const char *SUITE = "host_flash_manager";


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash_mock The mock for the flash state storage.
 * @param flash The flash device to initialize for state.
 */
static void host_flash_manager_testing_init_host_state (CuTest *test,
	struct state_manager *state, struct flash_master_mock *flash_mock, struct spi_flash *flash)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (flash, &flash_mock->base);
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

/**
 * Check that state persistence works.  This verifies that state persistence is not being blocked
 * after returning from flash manager calls.
 *
 * @param test The testing framework.
 * @param state The state manager to test against.
 * @param flash_mock The flash master used for the state manager.
 */
static void host_flash_manager_testing_check_state_persistence (CuTest *test,
		struct state_manager *state, struct flash_master_mock *flash_mock)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= mock_expect (&flash_mock->mock, flash_mock->base.xfer, flash_mock, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= mock_expect (&flash_mock->mock, flash_mock->base.xfer, flash_mock, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_erase_flash_sector_verify (flash_mock, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	state_manager_store_non_volatile_state (state);
}

/**
 * Execute device initialization for a flash device.
 *
 * @param test The testing framework.
 * @param flash The SPI flash to initialize.
 * @param mock The flash mock for the SPI device.
 * @param id ID of the flash device.
 */
static void host_flash_manager_testing_initialize_flash_device (CuTest *test,
	struct spi_flash *flash, struct flash_master_mock *mock, const uint8_t *id)
{
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
	uint8_t mode_expected[] = {0x20};
	int status;

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock->mock, mock->base.capabilities, mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (flash, &mock->base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock->mock);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void host_flash_manager_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_read_only_flash);
	CuAssertPtrNotNull (test, manager.get_read_write_flash);
	CuAssertPtrNotNull (test, manager.validate_read_only_flash);
	CuAssertPtrNotNull (test, manager.validate_read_write_flash);
	CuAssertPtrNotNull (test, manager.get_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.config_spi_filter_flash_type);
	CuAssertPtrNotNull (test, manager.config_spi_filter_flash_devices);
	CuAssertPtrNotNull (test, manager.swap_flash_devices);
	CuAssertPtrNotNull (test, manager.initialize_flash_protection);
	CuAssertPtrNotNull (test, manager.set_flash_for_rot_access);
	CuAssertPtrNotNull (test, manager.set_flash_for_host_access);
	CuAssertPtrNotNull (test, manager.host_has_flash_access);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (NULL, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init (&manager, NULL, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init (&manager, &flash0, NULL, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, NULL, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, NULL,
		&handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_init_with_managed_flash_initialization (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_initialization flash_init;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&flash_init, &flash0, &flash_mock0.base, &flash1,
		&flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.get_read_only_flash);
	CuAssertPtrNotNull (test, manager.get_read_write_flash);
	CuAssertPtrNotNull (test, manager.validate_read_only_flash);
	CuAssertPtrNotNull (test, manager.validate_read_write_flash);
	CuAssertPtrNotNull (test, manager.get_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.config_spi_filter_flash_type);
	CuAssertPtrNotNull (test, manager.config_spi_filter_flash_devices);
	CuAssertPtrNotNull (test, manager.swap_flash_devices);
	CuAssertPtrNotNull (test, manager.initialize_flash_protection);
	CuAssertPtrNotNull (test, manager.set_flash_for_rot_access);
	CuAssertPtrNotNull (test, manager.set_flash_for_host_access);
	CuAssertPtrNotNull (test, manager.host_has_flash_access);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	host_flash_initialization_release (&flash_init);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_init_with_managed_flash_initialization_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_initialization flash_init;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&flash_init, &flash0, &flash_mock0.base, &flash1,
		&flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init_with_managed_flash_initialization (NULL, &flash0, &flash1,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, NULL, &flash1,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, NULL,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		NULL, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, NULL, &handler.base, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, &filter.base, NULL, &flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, &filter.base, &handler.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	host_flash_initialization_release (&flash_init);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_release_null (CuTest *test)
{
	TEST_START;

	host_flash_manager_release (NULL);
}

static void host_flash_manager_test_get_read_only_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_read_only_flash (&manager);
	CuAssertPtrEquals (test, &flash0, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_read_only_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_read_only_flash (&manager);
	CuAssertPtrEquals (test, &flash1, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_read_only_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_read_only_flash (NULL);
	CuAssertPtrEquals (test, NULL, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_read_write_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *inactive;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	inactive = manager.get_read_write_flash (&manager);
	CuAssertPtrEquals (test, &flash1, inactive);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_read_write_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *inactive;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	inactive = manager.get_read_write_flash (&manager);
	CuAssertPtrEquals (test, &flash0, inactive);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_read_write_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct spi_flash *inactive;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	inactive = manager.get_read_write_flash (NULL);
	CuAssertPtrEquals (test, NULL, inactive);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock0, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_activate_pending_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_manager_mock pending;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock0, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&pending.mock, pending.base.base.activate_pending_manifest, &pending, 0);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, &pending.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_no_data_migration (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = manager.swap_flash_devices (NULL, &rw_list, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_dirty_clear_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter,
		SPI_FILTER_CLEAR_DIRTY_FAILED);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, SPI_FILTER_CLEAR_DIRTY_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_spi_filter_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, SPI_FILTER_SET_RO_FAILED,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, SPI_FILTER_SET_RO_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_cs1_data_copy_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_cs0_data_copy_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, NULL);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_swap_flash_devices_activate_pending_pfm_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_manager_mock pending;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock0, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&pending.mock, pending.base.base.activate_pending_manifest, &pending,
		MANIFEST_MANAGER_NONE_PENDING);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.swap_flash_devices (&manager, &rw_list, &pending.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = mock_validate (&flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_check_state_persistence (test, &host_state, &flash_mock_state);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_devices_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_devices_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_devices (&manager);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_devices_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_devices (NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_devices_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, SPI_FILTER_SET_RO_FAILED,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_devices (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_RO_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_validate_read_only_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs0_full_validation (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs1_full_validation (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock1, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&flash_mock1, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_full_validation_not_blank_byte (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0x45;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_value_check (&flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data), 0x45);
	status |= flash_master_mock_expect_value_check (&flash_mock0, 0x300, 0x1000 - 0x300, 0x45);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs0_good_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = 0x100;

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm_good.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm_good.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&pfm_good.mock, pfm_good.base.free_firmware_images, &pfm_good, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs1_good_pfm (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = 0x100;

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm_good.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm_good.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&pfm_good.mock, pfm_good.base.free_firmware_images, &pfm_good, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs0_good_pfm_no_match_image (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list img_list1;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_region img_region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list img_list2;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region1.start_addr = 0;
	img_region1.length = strlen (img_data);

	sig1.regions = &img_region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	img_list1.images = &sig1;
	img_list1.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	img_region2.start_addr = 0;
	img_region2.length = strlen (img_data);

	sig2.regions = &img_region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	img_list2.images = &sig2;
	img_list2.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list1, sizeof (img_list1), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm_good.mock, 1, &img_list2, sizeof (img_list2), -1);
	status |= mock_expect_save_arg (&pfm_good.mock, 1, 1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&pfm_good.mock, pfm_good.base.free_firmware_images, &pfm_good, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_cs1_good_pfm_no_match_image (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list img_list1;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_region img_region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list img_list2;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region1.start_addr = 0;
	img_region1.length = strlen (img_data);

	sig1.regions = &img_region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	img_list1.images = &sig1;
	img_list1.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	img_region2.start_addr = 0;
	img_region2.length = strlen (img_data);

	sig2.regions = &img_region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	img_list2.images = &sig2;
	img_list2.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list1, sizeof (img_list1), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm_good.mock, 1, &img_list2, sizeof (img_list2), -1);
	status |= mock_expect_save_arg (&pfm_good.mock, 1, 1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&pfm_good.mock, pfm_good.base.free_firmware_images, &pfm_good, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_full_validation (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (NULL, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_only_flash (&manager, NULL, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, NULL, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, NULL,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_pfm_version_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, PFM_GET_VERSIONS_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_pfm_images_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, PFM_GET_FW_IMAGES_FAILED,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_pfm_rw_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG (&rw_output));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_flash_version_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_flash_image_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 2);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_read_write_regions, &pfm, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_full_flash_image_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 2);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_read_write_regions, &pfm, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, NULL, &hash.base, &rsa.base,
		true, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_version_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, PFM_GET_VERSIONS_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_flash_version_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_images_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, PFM_GET_FW_IMAGES_FAILED,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_rw_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = 0x100;

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG (&rw_output));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_good_images_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good,
		PFM_GET_FW_IMAGES_FAILED, MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_only_flash_good_pfm_flash_image_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list img_list1;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_region img_region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list img_list2;
	struct pfm_mock pfm;
	struct pfm_mock pfm_good;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	img_region1.start_addr = 0;
	img_region1.length = strlen (img_data);

	sig1.regions = &img_region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	img_list1.images = &sig1;
	img_list1.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	img_region2.start_addr = 0;
	img_region2.length = strlen (img_data);

	sig2.regions = &img_region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	img_list2.images = &sig2;
	img_list2.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list1, sizeof (img_list1), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm_good.mock, pfm_good.base.get_firmware_images, &pfm_good, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm_good.mock, 1, &img_list2, sizeof (img_list2), -1);
	status |= mock_expect_save_arg (&pfm_good.mock, 1, 1);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_read_write_regions, &pfm, 0,
		MOCK_ARG (&rw_output));
	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&pfm_good.mock, pfm_good.base.free_firmware_images, &pfm_good, 0,
		MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_only_flash (&manager, &pfm.base, &pfm_good.base, &hash.base,
		&rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock1, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&flash_mock1, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_not_blank_byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xaa;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_value_check (&flash_mock1, 0 + strlen (img_data),
		0x200 - strlen (img_data), 0xaa);
	status |= flash_master_mock_expect_value_check (&flash_mock1, 0x300, 0x1000 - 0x300, 0xaa);

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (NULL, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_write_flash (&manager, NULL, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, NULL, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, NULL,
		&rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_pfm_version_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, PFM_GET_VERSIONS_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_pfm_images_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, PFM_GET_FW_IMAGES_FAILED,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_pfm_rw_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG (&rw_output));

	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_version_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_validate_read_write_flash_verify_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	img_region.start_addr = 0;
	img_region.length = strlen (img_data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_firmware_images, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 1, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 1, 1);

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_read_write_regions, &pfm, 0,
		MOCK_ARG (&rw_output));
	status |= mock_expect (&pfm.mock, pfm.base.free_firmware_images, &pfm, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.validate_read_write_flash (&manager, &pfm.base, &hash.base, &rsa.base,
		&rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_flash_manager_test_set_flash_for_rot_access (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t addr_mode = 0x20;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash0);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_4byte_address_mode (&flash1);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_not_initilized_device (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t addr_mode = 0x20;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	// CuAssertIntEquals (test, 0, status);

	mock_validate (&flash_mock0.mock);

	status = spi_flash_is_4byte_address_mode (&flash0);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_4byte_address_mode (&flash1);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_check_qspi_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t addr_mode = 0x20;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash0);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_4byte_address_mode (&flash1);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_wip_set (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t wip_set = FLASH_STATUS_WIP;
	uint8_t addr_mode = 0x20;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &wip_set, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &wip_set, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &wip_set, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash0);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_4byte_address_mode (&flash1);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_with_flash_initialization (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_initialization flash_init;
	struct host_control_mock control;
	struct host_flash_manager manager;
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
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint8_t qspi_enable = 0x40;
	uint8_t addr_mode = 0x20;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = host_flash_initialization_init (&flash_init, &flash0, &flash_mock0.base, &flash1,
		&flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Initialize flash devices. */

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Prepare devices. */

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash0);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_4byte_address_mode (&flash1);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	host_flash_initialization_release (&flash_init);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (NULL, &control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.set_flash_for_rot_access (&manager, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_filter_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter,
		SPI_FILTER_ENABLE_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, SPI_FILTER_ENABLE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_mux_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control,
		HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_wip_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_block_protect_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_qspi_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_4byte_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	host_flash_manager_testing_initialize_flash_device (test, &flash0, &flash_mock0, id);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	host_flash_manager_testing_initialize_flash_device (test, &flash1, &flash_mock1, id);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_id_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_unknown_id_ff (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xff, 0xff, 0xff};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_VENDOR, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_unknown_id_00 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0x00, 0x00, 0x00};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_VENDOR, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_rot_access_with_flash_initialization_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_initialization flash_init;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = host_flash_initialization_init (&flash_init, &flash0, &flash_mock0.base, &flash1,
		&flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init_with_managed_flash_initialization (&manager, &flash0, &flash1,
		&host_state, &filter.base, &handler.base, &flash_init);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (false));

	/* Initialize flash devices. */

	/* Get Device ID. */
	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_rot_access (&manager, &control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	host_flash_initialization_release (&flash_init);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_host_access (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (true));

	/* Enable SPI filter. */
	status |= mock_expect (&filter.mock, filter.base.enable_filter, &filter, 0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_host_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_host_access_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_host_access (NULL, &control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.set_flash_for_host_access (&manager, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_host_access_mux_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control,
		HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_host_access (&manager, &control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_set_flash_for_host_access_enable_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Switch SPI mux. */
	status |= mock_expect (&control.mock, control.base.enable_processor_flash_access, &control, 0,
		MOCK_ARG (true));

	/* Enable SPI filter. */
	status |= mock_expect (&filter.mock, filter.base.enable_filter, &filter,
		SPI_FILTER_ENABLE_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.set_flash_for_host_access (&manager, &control.base);
	CuAssertIntEquals (test, SPI_FILTER_ENABLE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_OPCODE (0xe9));

	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_OPCODE (0xb7));

	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_require_write_enable (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (true));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_3byte (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));
	status |= mock_expect (&filter.mock, filter.base.set_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_4byte (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));
	status |= mock_expect (&filter.mock, filter.base.set_fixed_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_4byte (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_set_size_unsupported (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_addr_mode_write_en_unsupported (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_unsupported (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_vendors (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id0[] = {0xc2, 0x20, 0x19};
	uint8_t id1[] = {0xef, 0x40, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id0, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id1, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_VENDOR, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_devices (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id0[] = {0xc2, 0x20, 0x19};
	uint8_t id1[] = {0xc2, 0x20, 0x18};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id0, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id1, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_DEVICE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_sizes (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_SIZES, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_require_write_enable (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params_we[] = {
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
	uint32_t params_no_we[] = {
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params_we,
		sizeof (params_we), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params_no_we,
		sizeof (params_no_we), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_ADDR_MODE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_control (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params_switch[] = {
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
	uint32_t params_fixed[] = {
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params_switch,
		sizeof (params_switch), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params_fixed,
		sizeof (params_fixed), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_ADDR_MODE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_fixed_addr_mode (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params_3b[] = {
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
	uint32_t params_4b[] = {
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params_3b,
		sizeof (params_3b), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params_4b,
		sizeof (params_4b), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_ADDR_MODE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_reset_addr_mode (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};
	uint8_t reset_3b[] = {~0x02};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, reset_3b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_ADDR_MODE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_id0_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_id1_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xe9));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode0_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode1_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_filter_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler,
		MFG_FILTER_HANDLER_SET_MFG_FAILED, MOCK_ARG (0xc2), MOCK_ARG (0x2019));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_SET_MFG_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_unsupported_mfg (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0x01, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler,
		MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR, MOCK_ARG (0x01), MOCK_ARG (0x2019));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_unsupported_dev (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x18};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler,
		MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE, MOCK_ARG (0xc2), MOCK_ARG (0x2018));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_filter_size_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter,
		SPI_FILTER_SET_SIZE_FAILED, MOCK_ARG (0x1000000));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_SIZE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_addr_mode_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter,
		SPI_FILTER_SET_ADDR_MODE_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_ADDR_MODE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, id, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x200000));
	status |= mock_expect (&filter.mock, filter.base.set_fixed_addr_byte_mode, &filter,
		SPI_FILTER_SET_FIXED_ADDR_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_FIXED_ADDR_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_addr_mode_write_en_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		SPI_FILTER_SET_WREN_REQ_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_WREN_REQ_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&handler.mock, handler.base.set_flash_manufacturer, &handler, 0,
		MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&filter.mock, filter.base.set_flash_size, &filter, 0,
		MOCK_ARG (0x1000000));
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.require_addr_byte_mode_write_enable, &filter,
		0, MOCK_ARG (false));
	status |= mock_expect (&filter.mock, filter.base.set_reset_addr_byte_mode, &filter,
		SPI_FILTER_SET_RESET_ADDR_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.config_spi_filter_flash_type (&manager);
	CuAssertIntEquals (test, SPI_FILTER_SET_RESET_ADDR_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs0_3byte_cs1_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs1_3byte_cs0_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock0, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs0_4byte_cs1_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify_4byte (&flash_mock1, 0x10000,
		RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify_4byte (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs1_4byte_cs0_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify_4byte (&flash_mock0, 0x10000,
		RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify_4byte (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs0_4byte_cs1_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_OPCODE (0xb7));

	status |= flash_master_mock_expect_erase_flash_verify_4byte (&flash_mock1, 0x10000,
		RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify_4byte (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs1_4byte_cs0_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_OPCODE (0xb7));

	status |= flash_master_mock_expect_erase_flash_verify_4byte (&flash_mock0, 0x10000,
		RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify_4byte (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs0_3byte_cs1_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash1, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_OPCODE (0xe9));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_cs1_3byte_cs0_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_OPCODE (0xe9));

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock0, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock0, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_1));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_fixed_3byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_fixed_4byte (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
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
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash0, &flash_mock0, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	spi_flash_testing_discover_params (test, &flash1, &flash_mock1, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = manager.initialize_flash_protection (NULL, &rw_list);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.initialize_flash_protection (&manager, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_flash_mode_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_data_copy_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_dirty_clear_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter,
		SPI_FILTER_CLEAR_DIRTY_FAILED);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_CLEAR_DIRTY_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_filter_mode_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter,
		SPI_FILTER_SET_ADDR_MODE_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_SET_ADDR_MODE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_bypass_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter,
		SPI_FILTER_SET_BYPASS_FAILED, MOCK_ARG (SPI_FILTER_OPERATE));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_SET_BYPASS_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_initialize_flash_protection_filter_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	spi_filter_cs active;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);
	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock1, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock1, &flash_mock0, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	status |= mock_expect (&filter.mock, filter.base.clear_flash_dirty_state, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_addr_byte_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&filter.mock, filter.base.set_bypass_mode, &filter, 0,
		MOCK_ARG (SPI_FILTER_OPERATE));
	status |= mock_expect (&filter.mock, filter.base.set_ro_cs, &filter, SPI_FILTER_SET_RO_FAILED,
		MOCK_ARG (SPI_FILTER_CS_0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = manager.initialize_flash_protection (&manager, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_SET_RO_FAILED, status);

	active = host_state_manager_get_read_only_flash (&host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_ro_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_ro_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_rw_flash_cs1 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_rw_flash_cs0 (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_state_manager_save_read_only_flash (&host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm, 0,
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG (&rw_output));
	status |= mock_expect_output (&pfm.mock, 1, &rw_list, sizeof (rw_list), -1);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (NULL, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.get_flash_read_write_regions (&manager, NULL, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_pfm_version_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, PFM_GET_VERSIONS_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_ro_flash_version_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_rw_flash_version_error (
	CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, true, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_get_flash_read_write_regions_pfm_rw_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_flash_manager manager;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct pfm_mock pfm;
	struct pfm_read_write_regions rw_output;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&flash0, 0x1000);
	status |= spi_flash_set_device_size (&flash1, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pfm.mock, pfm.base.get_supported_versions, &pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&pfm.mock, 0, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&pfm.mock, 0, 0);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&pfm.mock, pfm.base.get_read_write_regions, &pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG (&rw_output));

	status |= mock_expect (&pfm.mock, pfm.base.free_fw_versions, &pfm, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = manager.get_flash_read_write_regions (&manager, &pfm.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	bool enabled = true;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.processor_has_flash_access, &control, 1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (&manager, &control.base);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access_rot_access (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	bool enabled = true;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.processor_has_flash_access, &control, 0);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access_filter_disabled (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	bool enabled = false;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.processor_has_flash_access, &control, 1);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (&manager, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (NULL, &control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.host_has_flash_access (&manager, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access_access_check_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;
	bool enabled = true;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.processor_has_flash_access, &control,
		HOST_CONTROL_FLASH_CHECK_FAILED);

	status |= mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (&manager, &control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_CHECK_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}

static void host_flash_manager_test_host_has_flash_access_filter_check_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct spi_flash flash_state;
	struct state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct flash_mfg_filter_handler_mock handler;
	struct host_control_mock control;
	struct host_flash_manager manager;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);
	flash_mock0.mock.name = "flash_master0";

	status = spi_flash_init (&flash0, &flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
	flash_mock1.mock.name = "flash_master1";

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_testing_init_host_state (test, &host_state, &flash_mock_state, &flash_state);

	status = host_flash_manager_init (&manager, &flash0, &flash1, &host_state, &filter.base,
		&handler.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&filter.mock, filter.base.get_filter_enabled, &filter,
		SPI_FILTER_GET_ENABLED_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.host_has_flash_access (&manager, &control.base);
	CuAssertIntEquals (test, SPI_FILTER_GET_ENABLED_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_release (&manager);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
	spi_flash_release (&flash_state);
}


CuSuite* get_host_flash_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, host_flash_manager_test_init);
	SUITE_ADD_TEST (suite, host_flash_manager_test_init_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_init_with_managed_flash_initialization);
	SUITE_ADD_TEST (suite, host_flash_manager_test_init_with_managed_flash_initialization_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_release_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_only_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_only_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_only_flash_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_write_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_write_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_read_write_flash_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_activate_pending_pfm);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_no_data_migration);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_dirty_clear_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_spi_filter_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_cs1_data_copy_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_cs0_data_copy_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_swap_flash_devices_activate_pending_pfm_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_devices_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_devices_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_devices_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_devices_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs0_full_validation);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs1_full_validation);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_full_validation_not_blank_byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs0_good_pfm);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_cs1_good_pfm);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_cs0_good_pfm_no_match_image);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_cs1_good_pfm_no_match_image);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_full_validation);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_pfm_version_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_pfm_images_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_pfm_rw_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_flash_version_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_flash_image_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_only_flash_full_flash_image_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_version_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_flash_version_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_images_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_pfm_rw_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_good_images_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_validate_read_only_flash_good_pfm_flash_image_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_not_blank_byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_pfm_version_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_pfm_images_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_pfm_rw_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_version_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_validate_read_write_flash_verify_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_not_initilized_device);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_check_qspi_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_wip_set);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_set_flash_for_rot_access_with_flash_initialization);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_filter_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_mux_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_wip_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_block_protect_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_qspi_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_4byte_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_id_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_unknown_id_ff);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_rot_access_unknown_id_00);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_set_flash_for_rot_access_with_flash_initialization_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_host_access);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_host_access_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_host_access_mux_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_set_flash_for_host_access_enable_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_4byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_3byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_4byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_require_write_enable);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_3byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_4byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_4byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_set_size_unsupported);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_addr_mode_write_en_unsupported);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_unsupported);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_diff_vendors);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_diff_devices);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_diff_sizes);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_require_write_enable);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_control);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_fixed_addr_mode);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_reset_addr_mode);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_id0_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_id1_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_diff_addr_mode_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode0_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_fixed_3byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_fixed_4byte);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode1_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_filter_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_unsupported_mfg);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_unsupported_dev);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_filter_size_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_addr_mode_write_en_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_config_spi_filter_flash_type_addr_mode_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_fixed_addr_mode_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_config_spi_filter_flash_type_reset_addr_mode_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs0_3byte_cs1_3byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs1_3byte_cs0_3byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs0_4byte_cs1_4byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs1_4byte_cs0_4byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs0_4byte_cs1_3byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs1_4byte_cs0_3byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs0_3byte_cs1_4byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_cs1_3byte_cs0_4byte);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_flash_mode_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_data_copy_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_dirty_clear_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_filter_mode_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_bypass_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_initialize_flash_protection_filter_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_ro_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_ro_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_rw_flash_cs1);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_rw_flash_cs0);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_pfm_version_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_get_flash_read_write_regions_ro_flash_version_error);
	SUITE_ADD_TEST (suite,
		host_flash_manager_test_get_flash_read_write_regions_rw_flash_version_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_get_flash_read_write_regions_pfm_rw_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access_rot_access);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access_filter_disabled);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access_null);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access_access_check_error);
	SUITE_ADD_TEST (suite, host_flash_manager_test_host_has_flash_access_filter_check_error);

	return suite;
}
