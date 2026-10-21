// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_common.h"
#include "system/system_state_manager.h"
#include "system/system_state_manager_static.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("system_state_manager");


/**
 * Dependencies for testing.
 */
struct system_state_manager_testing {
	struct flash_mock flash;			/**< Mock for the state flash. */
	struct state_manager_state state;	/**< Variable context for the state manager. */
	struct state_manager test;			/**< State manager being tested. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 */
static void system_state_manager_testing_init_dependencies (CuTest *test,
	struct system_state_manager_testing *manager)
{
	int status;

	status = flash_mock_init (&manager->flash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void system_state_manager_testing_release_dependencies (CuTest *test,
	struct system_state_manager_testing *manager)
{
	int status;

	status = flash_mock_validate_and_release (&manager->flash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param manager Testing components to release.
 */
static void system_state_manager_testing_release (CuTest *test,
	struct system_state_manager_testing *manager)
{
	system_state_manager_release (&manager->test);
	system_state_manager_testing_release_dependencies (test, manager);
}

/**
 * Initialize the system state manager for testing.  The manager will be initialized with default
 * values.
 *
 * @param test The testing framework.
 * @param manager The system state instance to initialize.
 * @param state Variable context for the manager.
 * @param flash The flash device to use for state storage.
 * @param init_flash Flag to have the flash mock also initialized.
 */
void system_state_manager_testing_init_system_state (CuTest *test, struct state_manager *manager,
	struct state_manager_state *state, struct flash_mock *flash, bool init_flash)
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

	status = system_state_manager_init (manager, state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void system_state_manager_test_init (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.nv_state);
	CuAssertIntEquals (test, 0x40, manager.state.volatile_state);

	CuAssertPtrNotNull (test, manager.test.get_active_manifest);
	CuAssertPtrNotNull (test, manager.test.save_active_manifest);
	CuAssertPtrNotNull (test, manager.test.restore_default_state);
	CuAssertPtrNotNull (test, manager.test.is_manifest_valid);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_init_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

	status = system_state_manager_init (NULL, &manager.state, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = system_state_manager_init (&manager.test, NULL, &manager.flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = system_state_manager_init (&manager.test, &manager.state, NULL, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	system_state_manager_testing_release_dependencies (test, &manager);
}

static void system_state_manager_test_init_not_sector_aligned (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status |= system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	system_state_manager_testing_release_dependencies (test, &manager);
}

static void system_state_manager_test_static_init (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	CuAssertPtrNotNull (test, manager.test.get_active_manifest);
	CuAssertPtrNotNull (test, manager.test.save_active_manifest);
	CuAssertPtrNotNull (test, manager.test.restore_default_state);
	CuAssertPtrNotNull (test, manager.test.is_manifest_valid);

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.nv_state);
	CuAssertIntEquals (test, 0x40, manager.state.volatile_state);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_static_init_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	struct state_manager null_state =
		system_state_manager_static_init (NULL, &manager.flash.base, 0x10000);
	struct state_manager null_flash =
		system_state_manager_static_init (&manager.state, NULL, 0x10000);
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

	status = system_state_manager_init_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = system_state_manager_init_state (&null_state);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = system_state_manager_init_state (&null_flash);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	system_state_manager_testing_release_dependencies (test, &manager);
}

static void system_state_manager_test_static_init_not_sector_aligned (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10100)
	};
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.flash.mock, manager.flash.base.get_sector_size, &manager.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status |= system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	system_state_manager_testing_release_dependencies (test, &manager);
}

static void system_state_manager_test_release_null (CuTest *test)
{
	TEST_START;

	system_state_manager_release (NULL);
}

static void system_state_manager_test_get_active_manifest_region1_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_region2_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_no_state_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_region1_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_region2_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_no_state_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_invalid (CuTest *test)
{
	struct system_state_manager_testing manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, NUM_SYSTEM_STATE_MANIFESTS);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_static_init_cfm (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_static_init_pcd (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_get_active_manifest_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (NULL, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_region1_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM,
		MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_region2_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_unknown_region_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM,
		(enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_same_region_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_region1_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_region2_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_unknown_region_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD,
		(enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_same_region_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_invalid_index (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.save_active_manifest (&manager.test, NUM_SYSTEM_STATE_MANIFESTS,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_OUT_OF_RANGE, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_static_init_cfm (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM,
		MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_static_init_pcd (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.test.save_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.test.get_active_manifest (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_save_active_manifest_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.save_active_manifest (NULL, SYSTEM_STATE_MANIFEST_CFM, MANIFEST_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_restore_default_state (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	status = manager.test.restore_default_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_restore_default_state_static_init (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	status = manager.test.restore_default_state (&manager.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_restore_default_state_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	status = manager.test.restore_default_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, 0xff80, manager.state.nv_state);
	CuAssertIntEquals (test, 0x00, manager.state.volatile_state);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_cfm (CuTest *test)
{
	struct system_state_manager_testing manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_pcd (CuTest *test)
{
	struct system_state_manager_testing manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_invalid (CuTest *test)
{
	struct system_state_manager_testing manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (&manager.test, NUM_SYSTEM_STATE_MANIFESTS);
	CuAssertIntEquals (test, STATE_MANAGER_OUT_OF_RANGE, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_static_init_cfm (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (&manager.test, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_static_init_pcd (CuTest *test)
{
	struct system_state_manager_testing manager = {
		.test = system_state_manager_static_init (&manager.state, &manager.flash.base, 0x10000)
	};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init_state (&manager.test);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (&manager.test, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_testing_release (test, &manager);
}

static void system_state_manager_test_is_manifest_valid_null (CuTest *test)
{
	struct system_state_manager_testing manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

	TEST_START;

	system_state_manager_testing_init_dependencies (test, &manager);

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

	status = system_state_manager_init (&manager.test, &manager.state, &manager.flash.base,
		0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.is_manifest_valid (NULL, 0);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_testing_release (test, &manager);
}

// *INDENT-OFF*
TEST_SUITE_START (system_state_manager);

TEST (system_state_manager_test_init);
TEST (system_state_manager_test_init_null);
TEST (system_state_manager_test_init_not_sector_aligned);
TEST (system_state_manager_test_static_init);
TEST (system_state_manager_test_static_init_null);
TEST (system_state_manager_test_static_init_not_sector_aligned);
TEST (system_state_manager_test_release_null);
TEST (system_state_manager_test_get_active_manifest_region1_cfm);
TEST (system_state_manager_test_get_active_manifest_region2_cfm);
TEST (system_state_manager_test_get_active_manifest_no_state_cfm);
TEST (system_state_manager_test_get_active_manifest_region1_pcd);
TEST (system_state_manager_test_get_active_manifest_region2_pcd);
TEST (system_state_manager_test_get_active_manifest_no_state_pcd);
TEST (system_state_manager_test_get_active_manifest_invalid);
TEST (system_state_manager_test_get_active_manifest_static_init_cfm);
TEST (system_state_manager_test_get_active_manifest_static_init_pcd);
TEST (system_state_manager_test_get_active_manifest_null);
TEST (system_state_manager_test_save_active_manifest_region1_cfm);
TEST (system_state_manager_test_save_active_manifest_region2_cfm);
TEST (system_state_manager_test_save_active_manifest_unknown_region_cfm);
TEST (system_state_manager_test_save_active_manifest_same_region_cfm);
TEST (system_state_manager_test_save_active_manifest_region1_pcd);
TEST (system_state_manager_test_save_active_manifest_region2_pcd);
TEST (system_state_manager_test_save_active_manifest_unknown_region_pcd);
TEST (system_state_manager_test_save_active_manifest_same_region_pcd);
TEST (system_state_manager_test_save_active_manifest_invalid_index);
TEST (system_state_manager_test_save_active_manifest_static_init_cfm);
TEST (system_state_manager_test_save_active_manifest_static_init_pcd);
TEST (system_state_manager_test_save_active_manifest_null);
TEST (system_state_manager_test_restore_default_state);
TEST (system_state_manager_test_restore_default_state_static_init);
TEST (system_state_manager_test_restore_default_state_null);
TEST (system_state_manager_test_is_manifest_valid_cfm);
TEST (system_state_manager_test_is_manifest_valid_pcd);
TEST (system_state_manager_test_is_manifest_valid_invalid);
TEST (system_state_manager_test_is_manifest_valid_static_init_cfm);
TEST (system_state_manager_test_is_manifest_valid_static_init_pcd);
TEST (system_state_manager_test_is_manifest_valid_null);

TEST_SUITE_END;
// *INDENT-ON*
