// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_flash_manager_single.h"
#include "host_fw/host_state_manager.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/mock/spi_filter/flash_mfg_filter_handler_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/flash/spi_flash_sfdp_testing.h"
#include "testing/flash/spi_flash_testing.h"


TEST_SUITE_LABEL ("host_flash_manager_single");


/**
 * Dependencies for testing.
 */
struct host_flash_manager_single_testing {
	HASH_TESTING_ENGINE hash;						/**< Hash engine for testing. */
	RSA_TESTING_ENGINE rsa;							/**< RSA engine for testing. */
	struct flash_master_mock flash_mock0;			/**< Mock for CS0 flash. */
	struct flash_master_mock flash_mock_state;		/**< Mock for host state flash. */
	struct spi_flash_state state0;					/**< CS0 flash device context. */
	struct spi_flash flash0;						/**< CS0 flash device. */
	struct spi_flash_state state;					/**< Host state flash context. */
	struct spi_flash flash_state;					/**< Host state flash device. */
	struct host_state_manager host_state;			/**< Host state. */
	struct spi_filter_interface_mock filter;		/**< Mock for the SPI filter. */
	struct flash_mfg_filter_handler_mock handler;	/**< Handler for SPI filter device config. */
	struct host_flash_initialization flash_init;	/**< Manager for flash initialization. */
	struct host_control_mock control;				/**< Mock for host control. */
	struct pfm_mock pfm;							/**< Mock PFM for testing. */
	struct pfm_mock pfm_good;						/**< Secondary mock PFM for testing. */
	struct host_flash_manager_single test;			/**< Flash manager under test. */
};

/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components.
 */
static void host_flash_manager_single_testing_init_host_state (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manager->flash_state, &manager->state,
		&manager->flash_mock_state.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash_state, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (&manager->flash_mock_state,
		0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager->host_state, &manager->flash_state.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the dependencies for flash manager testing, but skip all SPI flash initialization.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 *
 */
static void host_flash_manager_single_testing_initialize_dependencies_no_flash_master (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manager->hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&manager->rsa);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&manager->filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_init (&manager->handler);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_init_host_state (test, manager);

	status = host_flash_initialization_init_single_flash (&manager->flash_init, &manager->flash0,
		&manager->state0, &manager->flash_mock0.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&manager->control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&manager->pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&manager->pfm_good);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the dependencies for flash manager testing, but skip the flash devices.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 *
 */
static void host_flash_manager_single_testing_initialize_dependencies_no_flash (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, manager);

	status = flash_master_mock_init (&manager->flash_mock0);
	CuAssertIntEquals (test, 0, status);
	manager->flash_mock0.mock.name = "flash_master0";
}

/**
 * Initialize the dependencies for flash manager testing.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 *
 */
static void host_flash_manager_single_testing_initialize_dependencies (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, manager);

	status = spi_flash_init (&manager->flash0, &manager->state0, &manager->flash_mock0.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash0, 0x1000000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the dependencies used for flash manager testing and validate all mocks.  Skip releasing
 * flash instances.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 *
 */
static void host_flash_manager_single_testing_validate_and_release_dependencies_no_flash (
	CuTest *test, struct host_flash_manager_single_testing *manager)
{
	int status;

	status = flash_master_mock_validate_and_release (&manager->flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&manager->filter);
	CuAssertIntEquals (test, 0, status);

	status = flash_mfg_filter_handler_mock_validate_and_release (&manager->handler);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&manager->control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&manager->pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&manager->pfm_good);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager->host_state);
	host_flash_initialization_release (&manager->flash_init);
	spi_flash_release (&manager->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
	RSA_TESTING_ENGINE_RELEASE (&manager->rsa);
}

/**
 * Release the dependencies used for flash manager testing and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 *
 */
static void host_flash_manager_single_testing_validate_and_release_dependencies (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	host_flash_manager_single_testing_validate_and_release_dependencies_no_flash (test, manager);
	spi_flash_release (&manager->flash0);
}

/**
 * Initialize a flash manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 */
static void host_flash_manager_single_testing_init (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;

	host_flash_manager_single_testing_initialize_dependencies (test, manager);

	status = host_flash_manager_single_init (&manager->test, &manager->flash0, &manager->host_state,
		&manager->filter.base, &manager->handler.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing components and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 *
 */
static void host_flash_manager_single_testing_validate_and_release (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	host_flash_manager_single_testing_validate_and_release_dependencies (test, manager);
	host_flash_manager_single_release (&manager->test);
}

/**
 * Check that state persistence works.  This verifies that state persistence is not being blocked
 * after returning from flash manager calls.
 *
 * @param test The testing framework.
 * @param manager The testing components.
 */
static void host_flash_manager_single_testing_check_state_persistence (CuTest *test,
	struct host_flash_manager_single_testing *manager)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= mock_expect (&manager->flash_mock_state.mock, manager->flash_mock_state.base.xfer,
		&manager->flash_mock_state, 0, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= mock_expect (&manager->flash_mock_state.mock, manager->flash_mock_state.base.xfer,
		&manager->flash_mock_state, 0, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_erase_flash_sector_verify (&manager->flash_mock_state,
		0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	state_manager_store_non_volatile_state (&manager->host_state.base);
}

/**
 * Execute device initialization for a flash device.
 *
 * @param test The testing framework.
 * @param flash The SPI flash to initialize.
 * @param state Variable context for the SPI flash.
 * @param mock The flash mock for the SPI device.
 * @param id ID of the flash device.
 */
static void host_flash_manager_single_testing_initialize_flash_device (CuTest *test,
	struct spi_flash *flash, struct spi_flash_state *state, struct flash_master_mock *mock,
	const uint8_t *id)
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

	status = spi_flash_initialize_device (flash, state, &mock->base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock->mock);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void host_flash_manager_single_test_init (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies (test, &manager);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.get_read_only_flash);
	CuAssertPtrNotNull (test, manager.test.base.get_read_write_flash);
	CuAssertPtrNotNull (test, manager.test.base.validate_read_only_flash);
	CuAssertPtrNotNull (test, manager.test.base.validate_read_write_flash);
	CuAssertPtrNotNull (test, manager.test.base.get_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.free_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.config_spi_filter_flash_type);
	CuAssertPtrNotNull (test, manager.test.base.config_spi_filter_flash_devices);
	CuAssertPtrNotNull (test, manager.test.base.swap_flash_devices);
	CuAssertPtrNotNull (test, manager.test.base.initialize_flash_protection);
	CuAssertPtrNotNull (test, manager.test.base.restore_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.set_flash_for_rot_access);
	CuAssertPtrNotNull (test, manager.test.base.set_flash_for_host_access);
	CuAssertPtrNotNull (test, manager.test.base.host_has_flash_access);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_init_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies (test, &manager);

	status = host_flash_manager_single_init (NULL, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init (&manager.test, NULL, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, NULL,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		NULL, &manager.handler.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release_dependencies (test, &manager);
}

static void host_flash_manager_single_test_init_with_managed_flash_initialization (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies (test, &manager);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.get_read_only_flash);
	CuAssertPtrNotNull (test, manager.test.base.get_read_write_flash);
	CuAssertPtrNotNull (test, manager.test.base.validate_read_only_flash);
	CuAssertPtrNotNull (test, manager.test.base.validate_read_write_flash);
	CuAssertPtrNotNull (test, manager.test.base.get_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.free_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.config_spi_filter_flash_type);
	CuAssertPtrNotNull (test, manager.test.base.config_spi_filter_flash_devices);
	CuAssertPtrNotNull (test, manager.test.base.swap_flash_devices);
	CuAssertPtrNotNull (test, manager.test.base.initialize_flash_protection);
	CuAssertPtrNotNull (test, manager.test.base.restore_flash_read_write_regions);
	CuAssertPtrNotNull (test, manager.test.base.set_flash_for_rot_access);
	CuAssertPtrNotNull (test, manager.test.base.set_flash_for_host_access);
	CuAssertPtrNotNull (test, manager.test.base.host_has_flash_access);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_init_with_managed_flash_initialization_null (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies (test, &manager);

	status = host_flash_manager_single_init_with_managed_flash_initialization (NULL,
		&manager.flash0, &manager.host_state, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		NULL, &manager.host_state, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, NULL, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, NULL, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, &manager.filter.base, NULL,
		&manager.flash_init);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, &manager.filter.base, &manager.handler.base,
		NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release_dependencies (test, &manager);
}

static void host_flash_manager_single_test_release_null (CuTest *test)
{
	TEST_START;

	host_flash_manager_single_release (NULL);
}

static void host_flash_manager_single_test_get_read_only_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct spi_flash *active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	active = manager.test.base.get_read_only_flash (&manager.test.base);
	CuAssertPtrEquals (test, &manager.flash0, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_read_only_flash_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct spi_flash *active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	active = manager.test.base.get_read_only_flash (NULL);
	CuAssertPtrEquals (test, NULL, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_read_write_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct spi_flash *inactive;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	inactive = manager.test.base.get_read_write_flash (&manager.test.base);
	CuAssertPtrEquals (test, &manager.flash0, inactive);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_read_write_flash_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct spi_flash *inactive;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	inactive = manager.test.base.get_read_write_flash (NULL);
	CuAssertPtrEquals (test, NULL, inactive);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, NULL);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_activate_pending_pfm (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	struct pfm_manager_mock pending;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	status = pfm_manager_mock_init (&pending);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&pending.mock, pending.base.base.activate_pending_manifest, &pending, 0);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, &pending.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	status = pfm_manager_mock_validate_and_release (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_no_data_migration (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = manager.test.base.swap_flash_devices (NULL, &rw_host, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_dirty_clear_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, SPI_FILTER_CLEAR_DIRTY_FAILED);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, NULL);
	CuAssertIntEquals (test, SPI_FILTER_CLEAR_DIRTY_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_allow_writes_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, SPI_FILTER_SET_ALLOW_WRITE_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, NULL);
	CuAssertIntEquals (test, SPI_FILTER_SET_ALLOW_WRITE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_spi_filter_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, NULL);
	CuAssertIntEquals (test, SPI_FILTER_SET_FILTER_MODE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_swap_flash_devices_activate_pending_pfm_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	struct pfm_manager_mock pending;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	status = pfm_manager_mock_init (&pending);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&pending.mock, pending.base.base.activate_pending_manifest, &pending,
		MANIFEST_MANAGER_NONE_PENDING);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.swap_flash_devices (&manager.test.base, &rw_host, &pending.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = mock_validate (&manager.flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_check_state_persistence (test, &manager);

	status = pfm_manager_mock_validate_and_release (&pending);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_devices (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_devices (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_devices_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.config_spi_filter_flash_devices (NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_devices_allow_writes_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, SPI_FILTER_SET_ALLOW_WRITE_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_devices (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_ALLOW_WRITE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_devices_mode_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_devices (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_FILTER_MODE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_single_fw (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_multiple_fw (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 7);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[2], sizeof (img_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 8);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 9);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data1,
		strlen (img_data1), FLASH_EXP_READ_CMD (0x03, 0x000, 0, -1, strlen (img_data1)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data2,
		strlen (img_data2), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (img_data2)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data3,
		strlen (img_data3), FLASH_EXP_READ_CMD (0x03, 0x600, 0, -1, strlen (img_data3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (7));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (8));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (9));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_full_validation (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_full_validation_not_blank_byte (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_value_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data), 0x45);
	status |= flash_master_mock_expect_value_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300,
		0x45);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_full_validation_single_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_full_validation_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[0].blank_byte = 0xff;

	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[1].blank_byte = 0xff;

	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;
	version[2].blank_byte = 0xff;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 7);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[2], sizeof (img_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 8);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 9);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (7));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data1,
		strlen (img_data1), FLASH_EXP_READ_CMD (0x03, 0x000, 0, -1, strlen (img_data1)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data2,
		strlen (img_data2), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (img_data2)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data3,
		strlen (img_data3), FLASH_EXP_READ_CMD (0x03, 0x600, 0, -1, strlen (img_data3)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x000 + strlen (img_data1), 0x200 - strlen (img_data1));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x300 + strlen (img_data2), 0x200 - strlen (img_data2));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x600 + strlen (img_data3), 0x200 - strlen (img_data3));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x900, 0x1000 - 0x900);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (8));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (9));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_single_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[0], sizeof (img_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[1], sizeof (img_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 5);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 7);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[2], sizeof (img_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 8);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 9);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[2], sizeof (img_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 8);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (8));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (7));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (8));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (9));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_no_match_image (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list img_list1;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct flash_region img_region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list img_list2;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list1.images_sig = &sig1;
	img_list1.images_hash = NULL;
	img_list1.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	img_region2.start_addr = 0;
	img_region2.length = strlen (img_data);

	sig2.regions = &img_region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	img_list2.images_sig = &sig2;
	img_list2.images_hash = NULL;
	img_list2.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list1, sizeof (img_list1), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list2, sizeof (img_list2), -1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_no_match_image_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[4];
	struct pfm_image_list img_list[4];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	sig[3].regions = &img_region[1];
	sig[3].count = 1;
	memcpy (&sig[3].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[3].signature, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN);
	sig[3].sig_length = RSA_ENCRYPT_LEN;
	sig[3].always_validate = 1;

	img_list[3].images_sig = &sig[3];
	img_list[3].images_hash = NULL;
	img_list[3].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[0], sizeof (img_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[3], sizeof (img_list[3]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 5);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 7);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[2], sizeof (img_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 8);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 9);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data1,
		strlen (img_data1), FLASH_EXP_READ_CMD (0x03, 0x000, 0, -1, strlen (img_data1)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data2,
		strlen (img_data2), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (img_data2)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data3,
		strlen (img_data3), FLASH_EXP_READ_CMD (0x03, 0x600, 0, -1, strlen (img_data3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (7));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (8));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (9));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_full_validation (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.validate_read_only_flash (NULL, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, NULL,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, NULL, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, NULL, false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_pfm_firmware_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm,
		PFM_GET_FW_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_pfm_version_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_pfm_version_error_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_pfm_images_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm,
		PFM_GET_FW_IMAGES_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_pfm_rw_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_flash_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_flash_image_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_full_flash_image_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.hash.base, &manager.rsa.base, true, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_firmware_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm,
		PFM_GET_FW_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_version_error_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[0], sizeof (img_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list[1], sizeof (img_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 5);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_flash_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_images_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm,
		PFM_GET_FW_IMAGES_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_rw_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_good_images_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, PFM_GET_FW_IMAGES_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_only_flash_good_pfm_flash_image_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	char *img_data = "Test";
	struct flash_region img_region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list img_list1;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct flash_region img_region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list img_list2;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list1.images_sig = &sig1;
	img_list1.images_hash = NULL;
	img_list1.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	img_region2.start_addr = 0;
	img_region2.length = strlen (img_data);

	sig2.regions = &img_region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	img_list2.images_sig = &sig2;
	img_list2.images_hash = NULL;
	img_list2.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list1, sizeof (img_list1), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.get_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm_good.mock, 2, &img_list2, sizeof (img_list2), -1);
	status |= mock_expect_save_arg (&manager.pfm_good.mock, 2, 1);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&manager.pfm_good.mock, manager.pfm_good.base.free_firmware_images,
		&manager.pfm_good, 0, MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_only_flash (&manager.test.base, &manager.pfm.base,
		&manager.pfm_good.base, &manager.hash.base, &manager.rsa.base, false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_not_blank_byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_value_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data), 0xaa);
	status |= flash_master_mock_expect_value_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300,
		0xaa);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_single_fw (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data,
		strlen (img_data), FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (img_data)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0 + strlen (img_data),
		0x200 - strlen (img_data));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x300, 0x1000 - 0x300);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_multiple_fw (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[0].blank_byte = 0xff;

	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[1].blank_byte = 0xff;

	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;
	version[2].blank_byte = 0xff;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 7);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[2], sizeof (img_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 8);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 9);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (7));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data1,
		strlen (img_data1), FLASH_EXP_READ_CMD (0x03, 0x000, 0, -1, strlen (img_data1)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data2,
		strlen (img_data2), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (img_data2)));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) img_data3,
		strlen (img_data3), FLASH_EXP_READ_CMD (0x03, 0x600, 0, -1, strlen (img_data3)));

	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x000 + strlen (img_data1), 0x200 - strlen (img_data1));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x300 + strlen (img_data2), 0x200 - strlen (img_data2));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0,
		0x600 + strlen (img_data3), 0x200 - strlen (img_data3));
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock0, 0x900, 0x1000 - 0x900);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (8));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (9));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.validate_read_write_flash (NULL, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, NULL,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		NULL, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, NULL, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_pfm_firmware_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm,
		PFM_GET_FW_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_pfm_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_pfm_version_error_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region img_region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list img_list[3];
	char *img_data1 = "Test";
	char *img_data2 = "Test2";
	char *img_data3 = "Nope";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[0].blank_byte = 0xff;

	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[1].blank_byte = 0xff;

	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;
	version[2].blank_byte = 0xff;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (img_data1);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_list[0].images_sig = &sig[0];
	img_list[0].images_hash = NULL;
	img_list[0].count = 1;

	img_region[1].start_addr = 0x300;
	img_region[1].length = strlen (img_data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list[1].images_sig = &sig[1];
	img_list[1].images_hash = NULL;
	img_list[1].count = 1;

	img_region[2].start_addr = 0x600;
	img_region[2].length = strlen (img_data3);

	sig[2].regions = &img_region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	img_list[2].images_sig = &sig[2];
	img_list[2].images_hash = NULL;
	img_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[0], sizeof (img_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 4);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list[1], sizeof (img_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 5);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (4));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (5));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_pfm_images_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm,
		PFM_GET_FW_IMAGES_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_IMAGES_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_pfm_rw_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_version_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;
	version.blank_byte = 0xff;

	version_list.versions = &version;
	version_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_validate_read_write_flash_verify_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	char *img_data = "Test";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

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

	img_list.images_sig = &sig;
	img_list.images_hash = NULL;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 3);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware_images, &manager.pfm, 0,
		MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &img_list, sizeof (img_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 2);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware_images, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.validate_read_write_flash (&manager.test.base, &manager.pfm.base,
		&manager.hash.base, &manager.rsa.base, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_free_read_write_regions_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions *rw_list;
	struct host_flash_manager_rw_regions rw_host;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list = platform_malloc (sizeof (struct pfm_read_write_regions));
	CuAssertPtrNotNull (test, rw_list);

	rw_list->regions = &rw_region;
	rw_list->properties = &rw_prop;
	rw_list->count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG (rw_list));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (NULL, &rw_host);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, NULL);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_free_read_write_regions_null_list (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = NULL;
	rw_host.count = 1;

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_host);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_free_read_write_regions_null_pfm (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = NULL;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_host);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t addr_mode = 0x20;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&manager.flash0);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_not_initilized_device (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t addr_mode = 0x20;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&manager.flash0);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_check_qspi_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t addr_mode = 0x20;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&manager.flash0);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_wip_set (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;
	uint8_t wip_set = FLASH_STATUS_WIP;
	uint8_t addr_mode = 0x20;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &wip_set, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &wip_set, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&manager.flash0);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_with_flash_initialization (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Initialize flash device. */

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) header,
		sizeof (header), FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) params,
		sizeof (params), FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&manager.flash_mock0.mock, manager.flash_mock0.base.capabilities,
		&manager.flash_mock0, FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Prepare device. */

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &addr_mode, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&manager.flash0);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.set_flash_for_rot_access (NULL, &manager.control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_filter_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		SPI_FILTER_ENABLE_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, SPI_FILTER_ENABLE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_mux_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control,
		HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_wip_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_block_protect_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_qspi_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_4byte_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};
	uint8_t bp_status = 0x3c;
	uint8_t qspi_enable = 0x40;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);
	host_flash_manager_single_testing_initialize_flash_device (test, &manager.flash0,
		&manager.state0, &manager.flash_mock0, id);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &bp_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &WIP_STATUS, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI mode. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &qspi_enable, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &qspi_enable, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect 4-byte addressing. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_id_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_unknown_id_ff (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xff, 0xff, 0xff};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_VENDOR, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_unknown_id_00 (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0x00, 0x00, 0x00};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Detect devices. */
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_VENDOR, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_rot_access_with_flash_initialization_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash (test, &manager);

	status = host_flash_manager_single_init_with_managed_flash_initialization (&manager.test,
		&manager.flash0, &manager.host_state, &manager.filter.base, &manager.handler.base,
		&manager.flash_init);
	CuAssertIntEquals (test, 0, status);

	/* Disable SPI filter. */
	status = mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (false));

	/* Switch SPI mux. */
	status |= mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (false));

	/* Initialize flash devices. */

	/* Get Device ID. */
	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_rot_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release_dependencies_no_flash (test, &manager);
	host_flash_manager_single_release (&manager.test);
}

static void host_flash_manager_single_test_set_flash_for_host_access (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Switch SPI mux. */
	status = mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (true));

	/* Enable SPI filter. */
	status |= mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		0, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_host_access (&manager.test.base,
		&manager.control.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_host_access_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.set_flash_for_host_access (NULL,
		&manager.control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.set_flash_for_host_access (&manager.test.base,
		NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_host_access_mux_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Switch SPI mux. */
	status = mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control,
		HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_host_access (&manager.test.base,
		&manager.control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_set_flash_for_host_access_enable_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Switch SPI mux. */
	status = mock_expect (&manager.control.mock,
		manager.control.base.enable_processor_flash_access, &manager.control, 0, MOCK_ARG (true));

	/* Enable SPI filter. */
	status |= mock_expect (&manager.filter.mock, manager.filter.base.enable_filter, &manager.filter,
		SPI_FILTER_ENABLE_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.set_flash_for_host_access (&manager.test.base,
		&manager.control.base);
	CuAssertIntEquals (test, SPI_FILTER_ENABLE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_4byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&manager.flash0, true);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.set_reset_addr_byte_mode, &manager.filter, 0,
		MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_require_write_enable (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		id, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x200000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_3byte (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		id, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x200000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_fixed_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_4byte (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		id, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x200000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_fixed_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
			MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_4byte (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_set_size_unsupported (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_write_en_unsupported (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter,
		SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_unsupported (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, SPI_FILTER_UNSUPPORTED_OPERATION, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.config_spi_filter_flash_type (NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_id_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_get_reset_addr_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xef), MOCK_ARG (0x4019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		reset_4b, 1, FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_filter_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, MFG_FILTER_HANDLER_SET_MFG_FAILED, MOCK_ARG (0xc2), MOCK_ARG (0x2019));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_SET_MFG_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_unsupported_mfg (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0x01, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR, MOCK_ARG (0x01),
		MOCK_ARG (0x2019));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_unsupported_dev (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x18};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE, MOCK_ARG (0xc2),
		MOCK_ARG (0x2018));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_filter_size_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, SPI_FILTER_SET_SIZE_FAILED, MOCK_ARG (0x2000000));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_SIZE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, SPI_FILTER_SET_ADDR_MODE_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_ADDR_MODE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		id, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x200000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_fixed_addr_byte_mode,
		&manager.filter, SPI_FILTER_SET_FIXED_ADDR_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_FIXED_ADDR_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_write_en_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter,
		SPI_FILTER_SET_WREN_REQ_FAILED, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_WREN_REQ_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	uint8_t id[] = {0xc2, 0x20, 0x19};

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	status |= mock_expect (&manager.handler.mock, manager.handler.base.set_flash_manufacturer,
		&manager.handler, 0, MOCK_ARG (0xc2), MOCK_ARG (0x2019));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_flash_size,
		&manager.filter, 0, MOCK_ARG (0x2000000));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock,
		manager.filter.base.require_addr_byte_mode_write_enable, &manager.filter, 0,
		MOCK_ARG (false));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_reset_addr_byte_mode,
		&manager.filter, SPI_FILTER_SET_RESET_ADDR_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.config_spi_filter_flash_type (&manager.test.base);
	CuAssertIntEquals (test, SPI_FILTER_SET_RESET_ADDR_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_3byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_4byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&manager.flash0, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_4));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_fixed_3byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		TEST_ID, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_fixed_4byte (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
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
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_initialize_dependencies_no_flash_master (test, &manager);
	spi_flash_testing_discover_params (test, &manager.flash0, &manager.state0, &manager.flash_mock0,
		TEST_ID, header, params, sizeof (params), 0x000030, FULL_CAPABILITIES);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	status = host_flash_manager_single_init (&manager.test, &manager.flash0, &manager.host_state,
		&manager.filter.base, &manager.handler.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_multiple_fw (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = RSA_ENCRYPT_LEN;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 16;
	rw_region[2].start_addr = 0x50000;
	rw_region[2].length = 32;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 3;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = manager.test.base.initialize_flash_protection (NULL, &rw_host);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.initialize_flash_protection (&manager.test.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_dirty_clear_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, SPI_FILTER_CLEAR_DIRTY_FAILED);

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, SPI_FILTER_CLEAR_DIRTY_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_filter_addr_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, SPI_FILTER_SET_ADDR_MODE_FAILED, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, SPI_FILTER_SET_ADDR_MODE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_allow_writes_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, SPI_FILTER_SET_ALLOW_WRITE_FAILED, MOCK_ARG (true));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, SPI_FILTER_SET_ALLOW_WRITE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_initialize_flash_protection_filter_flash_mode_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	spi_filter_cs active;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);
	host_state_manager_save_inactive_dirty (&manager.host_state, true);

	/* Set the device size to support 4-byte addressing. */
	status = spi_flash_set_device_size (&manager.flash0, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&manager.filter.mock, manager.filter.base.clear_flash_dirty_state,
		&manager.filter, 0);
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_addr_byte_mode,
		&manager.filter, 0, MOCK_ARG (SPI_FILTER_ADDRESS_MODE_3));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.allow_all_single_flash_writes,
		&manager.filter, 0, MOCK_ARG (true));
	status |= mock_expect (&manager.filter.mock, manager.filter.base.set_filter_mode,
		&manager.filter, SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&manager.host_state));

	status = manager.test.base.initialize_flash_protection (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, SPI_FILTER_SET_FILTER_MODE_FAILED, status);

	active = host_state_manager_get_read_only_flash (&manager.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, active);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&manager.host_state));

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_ro_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_single_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 3);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 4);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 5);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (5));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (4));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_rw_flash (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_single_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = "fw1";
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp, strlen (fw_exp) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable->count);
	CuAssertPtrEquals (test, &rw_region, (void*) rw_output.writable->regions);
	CuAssertPtrEquals (test, &rw_prop, (void*) rw_output.writable->properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 3);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 4);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[2], sizeof (version_list[2]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 5);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp3,
		strlen (version_exp3), FLASH_EXP_READ_CMD (0x03, 0x789, 0, -1, strlen (version_exp3)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp3, strlen (version_exp3) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[2], sizeof (rw_list[2]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 6);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (5));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		true, &rw_output);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 3, rw_output.count);
	CuAssertPtrNotNull (test, rw_output.writable);
	CuAssertPtrEquals (test, &manager.pfm, rw_output.pfm);

	CuAssertIntEquals (test, 1, rw_output.writable[0].count);
	CuAssertPtrEquals (test, &rw_region[0], (void*) rw_output.writable[0].regions);
	CuAssertPtrEquals (test, &rw_prop[0], (void*) rw_output.writable[0].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[1].count);
	CuAssertPtrEquals (test, &rw_region[1], (void*) rw_output.writable[1].regions);
	CuAssertPtrEquals (test, &rw_prop[1], (void*) rw_output.writable[1].properties);

	CuAssertIntEquals (test, 1, rw_output.writable[2].count);
	CuAssertPtrEquals (test, &rw_region[2], (void*) rw_output.writable[2].regions);
	CuAssertPtrEquals (test, &rw_prop[2], (void*) rw_output.writable[2].properties);

	status = mock_validate (&manager.flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.pfm.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions, &manager.pfm,
		0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (4));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (6));

	CuAssertIntEquals (test, 0, status);

	manager.test.base.free_read_write_regions (&manager.test.base, &rw_output);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.get_flash_read_write_regions (NULL, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, NULL,
		false, &rw_output);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_pfm_firmware_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm,
		PFM_GET_FW_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_FW_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_pfm_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_pfm_version_error_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 3);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[1], sizeof (rw_list[1]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 4);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	/* FW 3 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		PFM_GET_VERSIONS_FAILED, MOCK_ARG_PTR_CONTAINS (fw_exp[2], strlen (fw_exp[2]) + 1),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (4));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_VERSIONS_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_version_error (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		true, &rw_output);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_pfm_rw_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp = NULL;
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	const char *version_exp = "1234";
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = &fw_exp;
	fw_list.count = 1;

	version.fw_version_id = version_exp;
	version.version_addr = 0x123;

	version_list.versions = &version;
	version_list.count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list, sizeof (version_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG (NULL),
		MOCK_ARG_PTR_CONTAINS (version_exp, strlen (version_exp) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_get_flash_read_write_regions_pfm_rw_error_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct pfm_firmware fw_list;
	const char *fw_exp[3] = {"fw1", "fw2", "fw3"};
	struct pfm_firmware_version version[3];
	struct pfm_firmware_versions version_list[3];
	const char *version_exp1 = "1234";
	const char *version_exp2 = "5678";
	const char *version_exp3 = "90ab";
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_output;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	fw_list.ids = fw_exp;
	fw_list.count = 3;

	version[0].fw_version_id = version_exp1;
	version[0].version_addr = 0x123;
	version[1].fw_version_id = version_exp2;
	version[1].version_addr = 0x456;
	version[2].fw_version_id = version_exp3;
	version[2].version_addr = 0x789;

	version_list[0].versions = &version[0];
	version_list[0].count = 1;
	version_list[1].versions = &version[1];
	version_list[1].count = 1;
	version_list[2].versions = &version[2];
	version_list[2].count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x500;
	rw_region[1].length = 0x100;
	rw_region[2].start_addr = 0x800;
	rw_region[2].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[2].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	status = spi_flash_set_device_size (&manager.flash0, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.pfm.mock, manager.pfm.base.get_firmware, &manager.pfm, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 0, &fw_list, sizeof (fw_list), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 0, 2);

	/* FW 1 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[0], sizeof (version_list[0]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 0);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp1,
		strlen (version_exp1), FLASH_EXP_READ_CMD (0x03, 0x123, 0, -1, strlen (version_exp1)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[0], strlen (fw_exp[0]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp1, strlen (version_exp1) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 2, &rw_list[0], sizeof (rw_list[0]), -1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 2, 1);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* FW 2 */
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_supported_versions, &manager.pfm,
		0, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.pfm.mock, 1, &version_list[1], sizeof (version_list[1]),
		-1);
	status |= mock_expect_save_arg (&manager.pfm.mock, 1, 3);

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock0, 0, (uint8_t*) version_exp2,
		strlen (version_exp2), FLASH_EXP_READ_CMD (0x03, 0x456, 0, -1, strlen (version_exp2)));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.get_read_write_regions, &manager.pfm,
		PFM_GET_READ_WRITE_FAILED, MOCK_ARG_PTR_CONTAINS (fw_exp[1], strlen (fw_exp[1]) + 1),
		MOCK_ARG_PTR_CONTAINS (version_exp2, strlen (version_exp2) + 1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_fw_versions, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_read_write_regions,
		&manager.pfm, 0, MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&manager.pfm.mock, manager.pfm.base.free_firmware, &manager.pfm, 0,
		MOCK_ARG_SAVED_ARG (2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.get_flash_read_write_regions (&manager.test.base, &manager.pfm.base,
		false, &rw_output);
	CuAssertIntEquals (test, PFM_GET_READ_WRITE_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	bool enabled = true;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.control.mock, manager.control.base.processor_has_flash_access,
		&manager.control, 1);

	status |= mock_expect (&manager.filter.mock, manager.filter.base.get_filter_enabled,
		&manager.filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 1, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access_rot_access (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	bool enabled = true;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.control.mock, manager.control.base.processor_has_flash_access,
		&manager.control, 0);

	status |= mock_expect (&manager.filter.mock, manager.filter.base.get_filter_enabled,
		&manager.filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access_filter_disabled (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	bool enabled = false;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.control.mock, manager.control.base.processor_has_flash_access,
		&manager.control, 1);

	status |= mock_expect (&manager.filter.mock, manager.filter.base.get_filter_enabled,
		&manager.filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, 0, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = manager.test.base.host_has_flash_access (NULL, &manager.control.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access_access_check_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;
	bool enabled = true;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.control.mock, manager.control.base.processor_has_flash_access,
		&manager.control, HOST_CONTROL_FLASH_CHECK_FAILED);

	status |= mock_expect (&manager.filter.mock, manager.filter.base.get_filter_enabled,
		&manager.filter, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.filter.mock, 0, &enabled, sizeof (enabled), -1);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_CHECK_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_host_has_flash_access_filter_check_error (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	status = mock_expect (&manager.filter.mock, manager.filter.base.get_filter_enabled,
		&manager.filter, SPI_FILTER_GET_ENABLED_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.host_has_flash_access (&manager.test.base, &manager.control.base);
	CuAssertIntEquals (test, SPI_FILTER_GET_ENABLED_FAILED, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_restore_flash_read_write_regions (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_region.start_addr = 0x20000;
	rw_region.length = 0x10000;

	rw_prop.on_failure = PFM_RW_ERASE;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = manager.test.base.restore_flash_read_write_regions (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, HOST_FLASH_MGR_UNSUPPORTED_OPERATION, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_restore_flash_read_write_regions_multiple_fw (
	CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct flash_region rw_region[3];
	struct pfm_read_write rw_prop[3];
	struct pfm_read_write_regions rw_list[3];
	struct host_flash_manager_rw_regions rw_host;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_region[0].start_addr = 0;
	rw_region[0].length = 0x10000;
	rw_region[1].start_addr = 0x40000;
	rw_region[1].length = 0x10000;
	rw_region[2].start_addr = 0x100000;
	rw_region[2].length = 0x10000;

	rw_prop[0].on_failure = PFM_RW_ERASE;
	rw_prop[1].on_failure = PFM_RW_ERASE;
	rw_prop[2].on_failure = PFM_RW_ERASE;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_list[2].regions = &rw_region[2];
	rw_list[2].properties = &rw_prop[2];
	rw_list[2].count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 3;

	status = manager.test.base.restore_flash_read_write_regions (&manager.test.base, &rw_host);
	CuAssertIntEquals (test, HOST_FLASH_MGR_UNSUPPORTED_OPERATION, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}

static void host_flash_manager_single_test_restore_flash_read_write_regions_null (CuTest *test)
{
	struct host_flash_manager_single_testing manager;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;
	int status;

	TEST_START;

	host_flash_manager_single_testing_init (test, &manager);

	rw_region.start_addr = 0x20000;
	rw_region.length = 0x10000;

	rw_prop.on_failure = PFM_RW_ERASE;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &manager.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = manager.test.base.restore_flash_read_write_regions (NULL, &rw_host);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	status = manager.test.base.restore_flash_read_write_regions (&manager.test.base, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_INVALID_ARGUMENT, status);

	host_flash_manager_single_testing_validate_and_release (test, &manager);
}


TEST_SUITE_START (host_flash_manager_single);

TEST (host_flash_manager_single_test_init);
TEST (host_flash_manager_single_test_init_null);
TEST (host_flash_manager_single_test_init_with_managed_flash_initialization);
TEST (host_flash_manager_single_test_init_with_managed_flash_initialization_null);
TEST (host_flash_manager_single_test_release_null);
TEST (host_flash_manager_single_test_get_read_only_flash);
TEST (host_flash_manager_single_test_get_read_only_flash_null);
TEST (host_flash_manager_single_test_get_read_write_flash);
TEST (host_flash_manager_single_test_get_read_write_flash_null);
TEST (host_flash_manager_single_test_swap_flash_devices);
TEST (host_flash_manager_single_test_swap_flash_devices_activate_pending_pfm);
TEST (host_flash_manager_single_test_swap_flash_devices_no_data_migration);
TEST (host_flash_manager_single_test_swap_flash_devices_null);
TEST (host_flash_manager_single_test_swap_flash_devices_dirty_clear_error);
TEST (host_flash_manager_single_test_swap_flash_devices_allow_writes_error);
TEST (host_flash_manager_single_test_swap_flash_devices_spi_filter_error);
TEST (host_flash_manager_single_test_swap_flash_devices_activate_pending_pfm_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_devices);
TEST (host_flash_manager_single_test_config_spi_filter_flash_devices_null);
TEST (host_flash_manager_single_test_config_spi_filter_flash_devices_allow_writes_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_devices_mode_error);
TEST (host_flash_manager_single_test_validate_read_only_flash);
TEST (host_flash_manager_single_test_validate_read_only_flash_single_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_full_validation);
TEST (host_flash_manager_single_test_validate_read_only_flash_full_validation_not_blank_byte);
TEST (host_flash_manager_single_test_validate_read_only_flash_full_validation_single_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_full_validation_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_single_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_no_match_image);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_no_match_image_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_full_validation);
TEST (host_flash_manager_single_test_validate_read_only_flash_null);
TEST (host_flash_manager_single_test_validate_read_only_flash_pfm_firmware_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_pfm_version_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_pfm_version_error_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_pfm_images_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_pfm_rw_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_flash_version_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_flash_image_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_full_flash_image_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_firmware_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_version_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_version_error_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_flash_version_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_images_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_pfm_rw_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_good_images_error);
TEST (host_flash_manager_single_test_validate_read_only_flash_good_pfm_flash_image_error);
TEST (host_flash_manager_single_test_validate_read_write_flash);
TEST (host_flash_manager_single_test_validate_read_write_flash_not_blank_byte);
TEST (host_flash_manager_single_test_validate_read_write_flash_single_fw);
TEST (host_flash_manager_single_test_validate_read_write_flash_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_write_flash_null);
TEST (host_flash_manager_single_test_validate_read_write_flash_pfm_firmware_error);
TEST (host_flash_manager_single_test_validate_read_write_flash_pfm_version_error);
TEST (host_flash_manager_single_test_validate_read_write_flash_pfm_version_error_multiple_fw);
TEST (host_flash_manager_single_test_validate_read_write_flash_pfm_images_error);
TEST (host_flash_manager_single_test_validate_read_write_flash_pfm_rw_error);
TEST (host_flash_manager_single_test_validate_read_write_flash_version_error);
TEST (host_flash_manager_single_test_validate_read_write_flash_verify_error);
TEST (host_flash_manager_single_test_free_read_write_regions_null);
TEST (host_flash_manager_single_test_free_read_write_regions_null_list);
TEST (host_flash_manager_single_test_free_read_write_regions_null_pfm);
TEST (host_flash_manager_single_test_set_flash_for_rot_access);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_not_initilized_device);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_check_qspi_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_wip_set);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_with_flash_initialization);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_null);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_filter_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_mux_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_wip_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_block_protect_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_qspi_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_4byte_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_id_error);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_unknown_id_ff);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_unknown_id_00);
TEST (host_flash_manager_single_test_set_flash_for_rot_access_with_flash_initialization_error);
TEST (host_flash_manager_single_test_set_flash_for_host_access);
TEST (host_flash_manager_single_test_set_flash_for_host_access_null);
TEST (host_flash_manager_single_test_set_flash_for_host_access_mux_error);
TEST (host_flash_manager_single_test_set_flash_for_host_access_enable_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_4byte);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_require_write_enable);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_3byte);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_4byte);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_4byte);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_set_size_unsupported);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_write_en_unsupported);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_unsupported);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_null);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_id_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_get_reset_addr_mode_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_filter_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_unsupported_mfg);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_unsupported_dev);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_filter_size_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_write_en_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_addr_mode_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_fixed_addr_mode_error);
TEST (host_flash_manager_single_test_config_spi_filter_flash_type_reset_addr_mode_error);
TEST (host_flash_manager_single_test_initialize_flash_protection_3byte);
TEST (host_flash_manager_single_test_initialize_flash_protection_4byte);
TEST (host_flash_manager_single_test_initialize_flash_protection_fixed_3byte);
TEST (host_flash_manager_single_test_initialize_flash_protection_fixed_4byte);
TEST (host_flash_manager_single_test_initialize_flash_protection_multiple_fw);
TEST (host_flash_manager_single_test_initialize_flash_protection_null);
TEST (host_flash_manager_single_test_initialize_flash_protection_dirty_clear_error);
TEST (host_flash_manager_single_test_initialize_flash_protection_filter_addr_mode_error);
TEST (host_flash_manager_single_test_initialize_flash_protection_allow_writes_error);
TEST (host_flash_manager_single_test_initialize_flash_protection_filter_flash_mode_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_ro_flash);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_single_fw);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_multiple_fw);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_rw_flash);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_single_fw);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_multiple_fw);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_null);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_pfm_firmware_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_pfm_version_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_pfm_version_error_multiple_fw);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_ro_flash_version_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_rw_flash_version_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_pfm_rw_error);
TEST (host_flash_manager_single_test_get_flash_read_write_regions_pfm_rw_error_multiple_fw);
TEST (host_flash_manager_single_test_host_has_flash_access);
TEST (host_flash_manager_single_test_host_has_flash_access_rot_access);
TEST (host_flash_manager_single_test_host_has_flash_access_filter_disabled);
TEST (host_flash_manager_single_test_host_has_flash_access_null);
TEST (host_flash_manager_single_test_host_has_flash_access_access_check_error);
TEST (host_flash_manager_single_test_host_has_flash_access_filter_check_error);
TEST (host_flash_manager_single_test_restore_flash_read_write_regions);
TEST (host_flash_manager_single_test_restore_flash_read_write_regions_multiple_fw);
TEST (host_flash_manager_single_test_restore_flash_read_write_regions_null);

TEST_SUITE_END;
