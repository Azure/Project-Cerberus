// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/system_state_manager.h"
#include "mock/flash_mock.h"
#include "flash/flash_common.h"


static const char *SUITE = "system_state_manager";


/*******************
 * Test cases
 *******************/

static void system_state_manager_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x40, manager.volatile_state);

	CuAssertPtrNotNull (test, manager.get_active_manifest);
	CuAssertPtrNotNull (test, manager.save_active_manifest);
	CuAssertPtrNotNull (test, manager.restore_default_state);
	CuAssertPtrNotNull (test, manager.is_manifest_valid);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = system_state_manager_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = system_state_manager_init (&manager, NULL, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void system_state_manager_test_init_not_sector_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status |= system_state_manager_init (&manager, &flash.base, 0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void system_state_manager_test_get_active_manifest_region1_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_region2_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_no_state_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_region1_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_region2_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	int status;

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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_no_state_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_invalid (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, NUM_SYSTEM_STATE_MANIFESTS);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_get_active_manifest_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (NULL, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_region1_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_region2_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff83, 0xff83, 0xff83, 0};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_unknown_region_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM,
		(enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_same_region_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_region1_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_region2_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff83, 0xff83, 0xff83, 0};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_unknown_region_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD,
		(enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_same_region_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.save_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	active = manager.get_active_manifest (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_invalid_index (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.save_active_manifest (&manager, NUM_SYSTEM_STATE_MANIFESTS, MANIFEST_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_OUT_OF_RANGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_save_active_manifest_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.save_active_manifest (NULL, SYSTEM_STATE_MANIFEST_CFM, MANIFEST_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_restore_default_state (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = manager.restore_default_state (&manager);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_restore_default_state_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = manager.restore_default_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, 0xff80, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_is_manifest_valid_cfm (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.is_manifest_valid (&manager, SYSTEM_STATE_MANIFEST_CFM);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_is_manifest_valid_pcd (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.is_manifest_valid (&manager, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_is_manifest_valid_invalid (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.is_manifest_valid (&manager, NUM_SYSTEM_STATE_MANIFESTS);
	CuAssertIntEquals (test, STATE_MANAGER_OUT_OF_RANGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

static void system_state_manager_test_is_manifest_valid_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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

	status = system_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.is_manifest_valid (NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	system_state_manager_release (&manager);
}

CuSuite* get_system_state_manager_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, system_state_manager_test_init);
	SUITE_ADD_TEST (suite, system_state_manager_test_init_null);
	SUITE_ADD_TEST (suite, system_state_manager_test_init_not_sector_aligned);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_region1_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_region2_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_no_state_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_region1_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_region2_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_no_state_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_invalid);
	SUITE_ADD_TEST (suite, system_state_manager_test_get_active_manifest_null);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_region1_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_region2_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_unknown_region_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_same_region_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_region1_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_region2_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_unknown_region_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_same_region_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_invalid_index);
	SUITE_ADD_TEST (suite, system_state_manager_test_save_active_manifest_null);
	SUITE_ADD_TEST (suite, system_state_manager_test_restore_default_state);
	SUITE_ADD_TEST (suite, system_state_manager_test_restore_default_state_null);
	SUITE_ADD_TEST (suite, system_state_manager_test_is_manifest_valid_cfm);
	SUITE_ADD_TEST (suite, system_state_manager_test_is_manifest_valid_pcd);
	SUITE_ADD_TEST (suite, system_state_manager_test_is_manifest_valid_invalid);
	SUITE_ADD_TEST (suite, system_state_manager_test_is_manifest_valid_null);

	return suite;
}
