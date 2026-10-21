// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_common.h"
#include "host_fw/host_state_manager.h"
#include "host_fw/host_state_manager_static.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_state_observer_mock.h"


TEST_SUITE_LABEL ("host_state_manager");


/**
 * Dependencies for testing.
 */
struct host_state_manager_testing {
	struct flash_mock flash;					/**< Mock for the state flash. */
	struct host_state_observer_mock observer;	/**< Mock for the state observer. */
	struct host_state_manager_state state;		/**< Variable context for the state manager. */
	struct host_state_manager test;				/**< Host state manager being tested. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 */
static void host_state_manager_testing_init_dependencies (CuTest *test,
	struct host_state_manager_testing *manager)
{
	int status;

	status = flash_mock_init (&manager->flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&manager->observer);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void host_state_manager_testing_release_dependencies (CuTest *test,
	struct host_state_manager_testing *manager)
{
	int status;

	status = flash_mock_validate_and_release (&manager->flash);
	status |= host_state_observer_mock_validate_and_release (&manager->observer);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void host_state_manager_testing_release (CuTest *test,
	struct host_state_manager_testing *manager)
{
	host_state_manager_release (&manager->test);
	host_state_manager_testing_release_dependencies (test, manager);
}

/**
 * Initialize the host state manager for testing.  The manager will be initialized with default
 * values.
 *
 * @param test The testing framework.
 * @param manager The host state instance to initialize.
 * @param state Variable context for the manager.
 * @param flash The flash device to use for state storage.
 * @param init_flash Flag to have the flash mock also initialized.
 */
void host_state_manager_testing_init_host_state (CuTest *test, struct host_state_manager *manager,
	struct host_state_manager_state *state, struct flash_mock *flash, bool init_flash)
{
	int status;
	uint32_t sector_size = 0x1000;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	if (init_flash) {
		status = flash_mock_init (flash);
		CuAssertIntEquals (test, 0, status);
	}

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&flash->mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output_tmp (&flash->mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output_tmp (&flash->mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (manager, state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void host_state_manager_test_init (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x41, manager.state.base.volatile_state);

	CuAssertPtrNotNull (test, manager.test.base.get_active_manifest);
	CuAssertPtrNotNull (test, manager.test.base.save_active_manifest);
	CuAssertPtrNotNull (test, manager.test.base.restore_default_state);
	CuAssertPtrNotNull (test, manager.test.base.is_manifest_valid);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_init_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = host_state_manager_init (NULL, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_init (&manager.test, NULL, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_init (&manager.test, &manager.state, NULL, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release_dependencies (test, &manager);
}

static void host_state_manager_test_init_not_sector_aligned (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	host_state_manager_testing_release_dependencies (test, &manager);
}

static void host_state_manager_test_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	CuAssertPtrNotNull (test, manager.test.base.get_active_manifest);
	CuAssertPtrNotNull (test, manager.test.base.save_active_manifest);
	CuAssertPtrNotNull (test, manager.test.base.restore_default_state);
	CuAssertPtrNotNull (test, manager.test.base.is_manifest_valid);

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x41, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_static_init_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	struct host_state_manager null_state =
		host_state_manager_static_init ((struct host_state_manager_state*) NULL,
		&manager.flash.base, 0x10000);
	struct host_state_manager null_flash = host_state_manager_static_init (&manager.state, NULL,
		0x10000);
	int status;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = host_state_manager_init_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_init_state (&null_state);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_init_state (&null_flash);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release_dependencies (test, &manager);
}

static void host_state_manager_test_static_init_not_sector_aligned (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10100)
	};
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	host_state_manager_testing_release_dependencies (test, &manager);
}

static void host_state_manager_test_release_null (CuTest *test)
{
	TEST_START;

	host_state_manager_release (NULL);
}

static void host_state_manager_test_get_read_only_flash_nv_config_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_nv_config_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_nv_config_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_nv_config_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_nv_config_null (CuTest *test)
{
	spi_filter_cs ro;

	TEST_START;

	ro = host_state_manager_get_read_only_flash_nv_config (NULL);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);
}

static void host_state_manager_test_save_read_only_flash_nv_config_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_unknown_cs (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, (spi_filter_cs) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_same_cs (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_flash_nv_config_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_flash_nv_config (NULL, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_valid_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_valid_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0080, 0x0080, 0x0080, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_not_valid_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0380, 0x0380, 0x0380, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_not_valid_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0280, 0x0280, 0x0280, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_has_read_only_flash_override_null (CuTest *test)
{
	bool override;

	TEST_START;

	override = host_state_manager_has_read_only_flash_override (NULL);
	CuAssertIntEquals (test, false, override);
}

static void host_state_manager_test_override_read_only_flash_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_unknown_cs (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	status = host_state_manager_override_read_only_flash (&manager.test, (spi_filter_cs) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_same_cs (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_override_read_only_flash_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (NULL, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_valid_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_valid_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0080, 0x0080, 0x0080, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_not_valid_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0380, 0x0380, 0x0380, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_not_valid_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0280, 0x0280, 0x0280, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_clear_read_only_flash_override (&manager.test);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, false, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_clear_read_only_flash_override_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool override;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_clear_read_only_flash_override (NULL);

	override = host_state_manager_has_read_only_flash_override (&manager.test);
	CuAssertIntEquals (test, true, override);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs0_no_override (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs1_no_override (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs0_override_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0181, 0x0181, 0x0181, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs0_override_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0081, 0x0081, 0x0081, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs1_override_cs0 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0180, 0x0180, 0x0180, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs1_override_cs1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0080, 0x0080, 0x0080, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs0_enable_cs1_override (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_cs1_enable_cs0_override (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0280, 0x0280, 0x0280, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_override_read_only_flash (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0x0081, 0x0081, 0x0081, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_flash_null (CuTest *test)
{
	spi_filter_cs ro;

	TEST_START;

	ro = host_state_manager_get_read_only_flash (NULL);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);
}

static void host_state_manager_test_is_inactive_dirty_not_dirty (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_inactive_dirty_dirty (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_inactive_dirty_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_inactive_dirty_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_inactive_dirty_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (NULL);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager.test, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	status = host_state_manager_save_inactive_dirty (&manager.test, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_same_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager.test, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = host_state_manager_save_inactive_dirty (&manager.test, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = host_state_manager_save_inactive_dirty (&manager.test, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash (
	CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = host_state_manager_save_inactive_dirty (&manager.test, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = host_state_manager_save_inactive_dirty (&manager.test, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager.test, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager.test, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_inactive_dirty_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (NULL, true);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_all (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffb0, 0xffb0, 0xffb0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_por_only (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_host_reset (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff90, 0xff90, 0xff90, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_run_time (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffa0, 0xffa0, 0xffa0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xffb0, 0xffb0, 0xffb0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_read_only_activation_events_null (CuTest *test)
{
	enum host_read_only_activation events;

	TEST_START;

	events = host_state_manager_get_read_only_activation_events (NULL);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);
}

static void host_state_manager_test_save_read_only_activation_events_all (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_ALL);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_por_only (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffb0, 0xffb0, 0xffb0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_host_reset (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffb0, 0xffb0, 0xffb0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_run_time (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffb0, 0xffb0, 0xffb0, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_invalid (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		(enum host_read_only_activation) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_same_setting (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_ALL);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_read_only_activation events;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY, events);

	status = host_state_manager_save_read_only_activation_events (&manager.test,
		HOST_READ_ONLY_ACTIVATE_ON_ALL);
	CuAssertIntEquals (test, 0, status);

	events = host_state_manager_get_read_only_activation_events (&manager.test);
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL, events);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_read_only_activation_events_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_activation_events (NULL,
		HOST_READ_ONLY_ACTIVATE_ON_ALL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_pfm_region1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff84, 0xff84, 0xff84, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_pfm_region2 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_pfm_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_pfm_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff84, 0xff84, 0xff84, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_pfm_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (NULL, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_region1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_region2 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff84, 0xff84, 0xff84, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_unknown_region (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0,
		(enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_same_region (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.base.save_active_manifest (&manager.test.base, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.base.get_active_manifest (&manager.test.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_pfm_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.save_active_manifest (NULL, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_manifest_valid (CuTest *test)
{
	struct host_state_manager_testing manager;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.is_manifest_valid (&manager.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_manifest_valid_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.is_manifest_valid (&manager.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_manifest_valid_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.is_manifest_valid (NULL, 0);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_pfm_dirty (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_pfm_dirty_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
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
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, false);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, true);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_pfm_dirty (&manager.test, true);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_pfm_dirty (&manager.test, true);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_pfm_dirty (&manager.test, false);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_pfm_dirty (&manager.test, false);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, false);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, true);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, false);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_set_pfm_dirty (&manager.test, true);

	dirty = host_state_manager_is_pfm_dirty (&manager.test);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_pfm_dirty_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_pfm_dirty (NULL, false);
}

static void host_state_manager_test_get_run_time_validation (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_run_time_validation_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
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
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_NONE);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_run_time_validation_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_NONE);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_run_time_validation_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status = mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_run_time_validation (&manager.test,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_NONE);

	validation = host_state_manager_get_run_time_validation (&manager.test);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_run_time_validation_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_run_time_validation (NULL, HOST_STATE_PREVALIDATED_FLASH);
}

static void host_state_manager_test_get_active_recovery_image_region1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_recovery_image_region2 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_recovery_image_no_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_recovery_image_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_get_active_recovery_image_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&manager.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_region1 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager.test, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_region2 (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (&manager.test, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_unknown_region (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager.test,
		(enum recovery_image_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_same_region (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (&manager.test, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager.test, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager.test, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_save_active_recovery_image_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (NULL, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = host_state_manager_get_active_recovery_image (&manager.test);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_restore_default_state (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0x0080, 0x0080, 0x0080, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0080, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager.test, false);
	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.restore_default_state (&manager.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_restore_default_state_no_change (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffbf, 0xffbf, 0xffbf, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffbf, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.restore_default_state (&manager.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_restore_default_state_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager.test, false);
	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = manager.test.base.restore_default_state (&manager.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_restore_default_state_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0x0080, 0x0080, 0x0080, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0080, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager.test, false);
	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_active_pfm,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_inactive_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock,
		manager.observer.base.on_read_only_activation_events, &manager.observer, 0,
		MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_active_recovery_image,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pfm_dirty,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_run_time_validation,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.restore_default_state (&manager.test.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_restore_default_state_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.state.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager.test, false);
	host_state_manager_set_run_time_validation (&manager.test, HOST_STATE_PREVALIDATED_FLASH);

	status = manager.test.base.restore_default_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, 0xff80, manager.state.base.nv_state);
	CuAssertIntEquals (test, 0x02, manager.state.base.volatile_state);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_bypass_mode (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_bypass_mode_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_testing_release (test, &manager);
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
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_bypass_mode (&manager.test, true);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_bypass_mode (&manager.test, false);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_bypass_mode_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_bypass_mode (&manager.test, true);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_bypass_mode (&manager.test, false);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_bypass_mode_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_bypass_mode,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_bypass_mode (&manager.test, true);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_bypass_mode (&manager.test, false);

	status = host_state_manager_is_bypass_mode (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_bypass_mode_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_bypass_mode (NULL, true);
}

static void host_state_manager_test_is_flash_supported (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_is_flash_supported_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_testing_release (test, &manager);
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
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_unsupported_flash (&manager.test, true);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_unsupported_flash (&manager.test, false);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_unsupported_flash_no_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_unsupported_flash (&manager.test, true);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_unsupported_flash (&manager.test, false);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_unsupported_flash_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_unsupported_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_unsupported_flash (&manager.test, true);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_unsupported_flash (&manager.test, false);

	status = host_state_manager_is_flash_supported (&manager.test);
	CuAssertIntEquals (test, true, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_set_unsupported_flash_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_unsupported_flash (NULL, true);
}

static void host_state_manager_test_add_observer_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (NULL, &manager.observer.base);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_add_observer (&manager.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_remove_observer (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_remove_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_remove_observer_static_init (CuTest *test)
{
	struct host_state_manager_testing manager = {
		.test = host_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_remove_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}

static void host_state_manager_test_remove_observer_null (CuTest *test)
{
	struct host_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	host_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&manager.flash.mock, manager.flash.base.read, &manager.flash, 0,
		MOCK_ARG (0x10008), MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&manager.flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager.test, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager.test, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_remove_observer (NULL, &manager.observer.base);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_remove_observer (&manager.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = mock_expect (&manager.observer.mock, manager.observer.base.on_read_only_flash,
		&manager.observer, 0, MOCK_ARG_PTR (&manager.test));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash_nv_config (&manager.test, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash_nv_config (&manager.test);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	host_state_manager_testing_release (test, &manager);
}


// *INDENT-OFF*
TEST_SUITE_START (host_state_manager);

TEST (host_state_manager_test_init);
TEST (host_state_manager_test_init_null);
TEST (host_state_manager_test_init_not_sector_aligned);
TEST (host_state_manager_test_static_init);
TEST (host_state_manager_test_static_init_null);
TEST (host_state_manager_test_static_init_not_sector_aligned);
TEST (host_state_manager_test_release_null);
TEST (host_state_manager_test_get_read_only_flash_nv_config_cs0);
TEST (host_state_manager_test_get_read_only_flash_nv_config_cs1);
TEST (host_state_manager_test_get_read_only_flash_nv_config_no_state);
TEST (host_state_manager_test_get_read_only_flash_nv_config_static_init);
TEST (host_state_manager_test_get_read_only_flash_nv_config_null);
TEST (host_state_manager_test_save_read_only_flash_nv_config_cs0);
TEST (host_state_manager_test_save_read_only_flash_nv_config_cs1);
TEST (host_state_manager_test_save_read_only_flash_nv_config_unknown_cs);
TEST (host_state_manager_test_save_read_only_flash_nv_config_same_cs);
TEST (host_state_manager_test_save_read_only_flash_nv_config_no_observer);
TEST (host_state_manager_test_save_read_only_flash_nv_config_static_init);
TEST (host_state_manager_test_save_read_only_flash_nv_config_null);
TEST (host_state_manager_test_has_read_only_flash_override_valid_cs0);
TEST (host_state_manager_test_has_read_only_flash_override_valid_cs1);
TEST (host_state_manager_test_has_read_only_flash_override_not_valid_cs0);
TEST (host_state_manager_test_has_read_only_flash_override_not_valid_cs1);
TEST (host_state_manager_test_has_read_only_flash_override_no_state);
TEST (host_state_manager_test_has_read_only_flash_override_static_init);
TEST (host_state_manager_test_has_read_only_flash_override_null);
TEST (host_state_manager_test_override_read_only_flash_cs0);
TEST (host_state_manager_test_override_read_only_flash_cs1);
TEST (host_state_manager_test_override_read_only_flash_unknown_cs);
TEST (host_state_manager_test_override_read_only_flash_same_cs);
TEST (host_state_manager_test_override_read_only_flash_no_observer);
TEST (host_state_manager_test_override_read_only_flash_static_init);
TEST (host_state_manager_test_override_read_only_flash_null);
TEST (host_state_manager_test_clear_read_only_flash_override_valid_cs0);
TEST (host_state_manager_test_clear_read_only_flash_override_valid_cs1);
TEST (host_state_manager_test_clear_read_only_flash_override_not_valid_cs0);
TEST (host_state_manager_test_clear_read_only_flash_override_not_valid_cs1);
TEST (host_state_manager_test_clear_read_only_flash_override_no_state);
TEST (host_state_manager_test_clear_read_only_flash_override_static_init);
TEST (host_state_manager_test_clear_read_only_flash_override_null);
TEST (host_state_manager_test_get_read_only_flash_cs0_no_override);
TEST (host_state_manager_test_get_read_only_flash_cs1_no_override);
TEST (host_state_manager_test_get_read_only_flash_cs0_override_cs0);
TEST (host_state_manager_test_get_read_only_flash_cs0_override_cs1);
TEST (host_state_manager_test_get_read_only_flash_cs1_override_cs0);
TEST (host_state_manager_test_get_read_only_flash_cs1_override_cs1);
TEST (host_state_manager_test_get_read_only_flash_no_state);
TEST (host_state_manager_test_get_read_only_flash_cs0_enable_cs1_override);
TEST (host_state_manager_test_get_read_only_flash_cs1_enable_cs0_override);
TEST (host_state_manager_test_get_read_only_flash_static_init);
TEST (host_state_manager_test_get_read_only_flash_null);
TEST (host_state_manager_test_is_inactive_dirty_not_dirty);
TEST (host_state_manager_test_is_inactive_dirty_dirty);
TEST (host_state_manager_test_is_inactive_dirty_no_state);
TEST (host_state_manager_test_is_inactive_dirty_static_init);
TEST (host_state_manager_test_is_inactive_dirty_null);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty);
TEST (host_state_manager_test_save_inactive_dirty_dirty);
TEST (host_state_manager_test_save_inactive_dirty_same_state);
TEST (host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_save_inactive_dirty_no_observer);
TEST (host_state_manager_test_save_inactive_dirty_static_init);
TEST (host_state_manager_test_save_inactive_dirty_null);
TEST (host_state_manager_test_get_read_only_activation_events_all);
TEST (host_state_manager_test_get_read_only_activation_events_por_only);
TEST (host_state_manager_test_get_read_only_activation_events_host_reset);
TEST (host_state_manager_test_get_read_only_activation_events_run_time);
TEST (host_state_manager_test_get_read_only_activation_events_no_state);
TEST (host_state_manager_test_get_read_only_activation_events_static_init);
TEST (host_state_manager_test_get_read_only_activation_events_null);
TEST (host_state_manager_test_save_read_only_activation_events_all);
TEST (host_state_manager_test_save_read_only_activation_events_por_only);
TEST (host_state_manager_test_save_read_only_activation_events_host_reset);
TEST (host_state_manager_test_save_read_only_activation_events_run_time);
TEST (host_state_manager_test_save_read_only_activation_events_invalid);
TEST (host_state_manager_test_save_read_only_activation_events_same_setting);
TEST (host_state_manager_test_save_read_only_activation_events_no_observer);
TEST (host_state_manager_test_save_read_only_activation_events_static_init);
TEST (host_state_manager_test_save_read_only_activation_events_null);
TEST (host_state_manager_test_get_active_pfm_region1);
TEST (host_state_manager_test_get_active_pfm_region2);
TEST (host_state_manager_test_get_active_pfm_no_state);
TEST (host_state_manager_test_get_active_pfm_static_init);
TEST (host_state_manager_test_get_active_pfm_null);
TEST (host_state_manager_test_save_active_pfm_region1);
TEST (host_state_manager_test_save_active_pfm_region2);
TEST (host_state_manager_test_save_active_pfm_unknown_region);
TEST (host_state_manager_test_save_active_pfm_same_region);
TEST (host_state_manager_test_save_active_pfm_no_observer);
TEST (host_state_manager_test_save_active_pfm_static_init);
TEST (host_state_manager_test_save_active_pfm_null);
TEST (host_state_manager_test_is_manifest_valid);
TEST (host_state_manager_test_is_manifest_valid_static_init);
TEST (host_state_manager_test_is_manifest_valid_null);
TEST (host_state_manager_test_is_pfm_dirty);
TEST (host_state_manager_test_is_pfm_dirty_static_init);
TEST (host_state_manager_test_is_pfm_dirty_null);
TEST (host_state_manager_test_set_pfm_dirty);
TEST (host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_set_pfm_dirty_no_observer);
TEST (host_state_manager_test_set_pfm_dirty_static_init);
TEST (host_state_manager_test_set_pfm_dirty_null);
TEST (host_state_manager_test_get_run_time_validation);
TEST (host_state_manager_test_get_run_time_validation_static_init);
TEST (host_state_manager_test_get_run_time_validation_null);
TEST (host_state_manager_test_set_run_time_validation);
TEST (host_state_manager_test_set_run_time_validation_no_observer);
TEST (host_state_manager_test_set_run_time_validation_static_init);
TEST (host_state_manager_test_set_run_time_validation_null);
TEST (host_state_manager_test_get_active_recovery_image_region1);
TEST (host_state_manager_test_get_active_recovery_image_region2);
TEST (host_state_manager_test_get_active_recovery_image_no_state);
TEST (host_state_manager_test_get_active_recovery_image_static_init);
TEST (host_state_manager_test_get_active_recovery_image_null);
TEST (host_state_manager_test_save_active_recovery_image_region1);
TEST (host_state_manager_test_save_active_recovery_image_region2);
TEST (host_state_manager_test_save_active_recovery_image_unknown_region);
TEST (host_state_manager_test_save_active_recovery_image_same_region);
TEST (host_state_manager_test_save_active_recovery_image_no_observer);
TEST (host_state_manager_test_save_active_recovery_image_static_init);
TEST (host_state_manager_test_save_active_recovery_image_null);
TEST (host_state_manager_test_restore_default_state);
TEST (host_state_manager_test_restore_default_state_no_change);
TEST (host_state_manager_test_restore_default_state_no_observer);
TEST (host_state_manager_test_restore_default_state_static_init);
TEST (host_state_manager_test_restore_default_state_null);
TEST (host_state_manager_test_is_bypass_mode);
TEST (host_state_manager_test_is_bypass_mode_static_init);
TEST (host_state_manager_test_is_bypass_mode_null);
TEST (host_state_manager_test_set_bypass_mode);
TEST (host_state_manager_test_set_bypass_mode_no_observer);
TEST (host_state_manager_test_set_bypass_mode_static_init);
TEST (host_state_manager_test_set_bypass_mode_null);
TEST (host_state_manager_test_is_flash_supported);
TEST (host_state_manager_test_is_flash_supported_static_init);
TEST (host_state_manager_test_is_flash_supported_null);
TEST (host_state_manager_test_set_unsupported_flash);
TEST (host_state_manager_test_set_unsupported_flash_no_observer);
TEST (host_state_manager_test_set_unsupported_flash_static_init);
TEST (host_state_manager_test_set_unsupported_flash_null);
TEST (host_state_manager_test_add_observer_null);
TEST (host_state_manager_test_remove_observer);
TEST (host_state_manager_test_remove_observer_static_init);
TEST (host_state_manager_test_remove_observer_null);

TEST_SUITE_END;
// *INDENT-ON*
