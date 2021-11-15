// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "state_manager/state_manager.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("state_manager");


/*******************
 * Test cases
 *******************/

static void state_manager_test_init (CuTest *test)
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x40, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x40, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end) , 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10003),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[3], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc2, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10801),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10802),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10803),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[3], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc2, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_second_sector (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
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
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc1, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_second_sector_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc1, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_last_byte (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw1[4] = {0x4040, 0x4040, 0x4040, 0x4040};
	uint16_t raw2[4] = {0x4040, 0x4040, 0x4040, 0x4140};
	uint8_t *state1 = (uint8_t*) raw1;
	uint8_t *state2 = (uint8_t*) raw2;
	int i;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw1, sizeof (raw1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw1, sizeof (raw1), 2);

	status = 0;
	for (i = 0x10000; i < 0x11ff8; i++) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(1));
		status |= mock_expect_output (&flash.mock, 1, &state1[i % sizeof (raw1)], 1, 2);
	}

	for (i = 0x11ff8; i < 0x12000; i++) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(1));
		status |= mock_expect_output (&flash.mock, 1, &state2[i - 0x11ff8], 1, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc1, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_last_byte_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw1[4] = {0x4040, 0x4040, 0x4040, 0x4040};
	uint16_t raw2[4] = {0x4040, 0x4040, 0x4040, 0x4140};
	uint8_t *state1 = (uint8_t*) raw1;
	uint8_t *state2 = (uint8_t*) raw2;
	int i;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw1, sizeof (raw1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw1, sizeof (raw1), 2);

	status = 0;
	for (i = 0x10800; i < 0x117f8; i++) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(1));
		status |= mock_expect_output (&flash.mock, 1, &state1[i % sizeof (raw1)], 1, 2);
	}

	for (i = 0x117f8; i < 0x11800; i++) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(1));
		status |= mock_expect_output (&flash.mock, 1, &state2[i - 0x117f8], 1, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc1, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_first_sector_low_state_count (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffc1, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_not_block_aligned (CuTest *test)
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

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x12000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x11000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x40, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_not_block_aligned_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x11000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.nv_state);
	CuAssertIntEquals (test, 0x40, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff82, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10808),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10810),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10818),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff82, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_second_sector_updated_format (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff81, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_second_sector_updated_format_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff81, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_last_entry_updated_format (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	int i;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status = 0;
	for (i = 0x10000; i < 0x11ff8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11ff8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff81, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_last_entry_updated_format_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	int i;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status = 0;
	for (i = 0x10800; i < 0x117f8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x117f8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff81, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_bit_errors (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0x22c4, 0x12b5, 0x13b4, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x12b4, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_bit_error_on_type (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xffc0, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0x22c4, 0x12b5, 0x13b4, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x12b4, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_double_bit_error_fakes_blank (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffbf, 0xffff, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffbf, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_triple_bit_error_fakes_blank (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xfffe};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffbf, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_updated_format_bit_error_both_types_cleared (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xffc0, 0xffc0, 0xff00, 0};
	uint16_t state2[4] = {0xffc1, 0xffc1, 0xff01, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff81, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_both_formats (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff82, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_latest_state_both_formats_second_sector (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff82, manager.nv_state);
	CuAssertIntEquals (test, 0x00, manager.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = state_manager_init (&manager, NULL, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void state_manager_test_init_sector_size_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_SECTOR_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void state_manager_test_init_not_sector_aligned (CuTest *test)
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

	status = state_manager_init (&manager, &flash.base, 0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void state_manager_test_init_not_sector_aligned_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void state_manager_test_init_read_error_first_sector (CuTest *test)
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

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_read_error_second_sector (CuTest *test)
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

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG (8));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end) , 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG(1));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_read_second_sector_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG(1));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_low_state_count_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG(1));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_low_state_count_second_sector_read_error (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG(1));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_updated_format_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG(8));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_find_state_updated_format_second_sector_read_error (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
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
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11000), MOCK_ARG_NOT_NULL, MOCK_ARG(8));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_init_erase_error (CuTest *test)
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

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_release_null (CuTest *test)
{
	TEST_START;

	state_manager_release (NULL);
}

static void state_manager_test_store_non_volatile_state (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xfffe;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
	uint32_t bytes = 2 * 1024;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xfffe;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_not_first (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff83, 0xff83, 0xff83, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10018), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG(sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_not_first_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff83, 0xff83, 0xff83, 0};
	uint32_t bytes = 2 * 1024;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10808),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10810),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10818),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10818), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG(sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_second_sector (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11008), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_second_sector_sector_not_4k (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
	uint32_t bytes = 2 * 1024;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11008), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_store_change_twice (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff83, 0xff83, 0xff83, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, expected, sizeof (expected), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_multiple_changes (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected2[4] = {0xff81, 0xff81, 0xff81, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x10010), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_second_sector (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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

	for (i = 0x10000; i < 0x10ff0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10ff0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x10ff0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x10ff8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_second_sector_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint32_t bytes = 1024 * 2;
	int i;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x10800; i < 0x10ff0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10ff0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x10ff0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x10ff8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_first_sector (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x11000; i < 0x11ff0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11ff0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x11ff0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x11ff8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_first_sector_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint32_t bytes = 1024 * 2;
	int i;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x11000; i < 0x117f0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x117f0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x117f0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x117f8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_write_twice_second_not_blank (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x10010), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_write_twice_first_not_blank (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x11008), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x11010), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_second_then_first (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint16_t expected4[4] = {0xff87, 0xff87, 0xff87, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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

	for (i = 0x10000; i < 0x10ff0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10ff0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x10ff0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x10ff8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected4),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected4, sizeof (expected4)),
		MOCK_ARG (sizeof (expected4)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Force the next write to wrap again. */
	manager.store_addr = 0x11ff8;
	manager.nv_state = 0xffc7;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_wrap_to_first_then_second (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected1[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected2[4] = {0xff83, 0xff83, 0xff83, 0};
	uint16_t expected3[4] = {0xff85, 0xff85, 0xff85, 0};
	uint16_t expected4[4] = {0xff87, 0xff87, 0xff87, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x11000; i < 0x11ff0; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11ff0),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected1),
		MOCK_ARG (0x11ff0), MOCK_ARG_PTR_CONTAINS (&expected1, sizeof (expected1)),
		MOCK_ARG (sizeof (expected1)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected2),
		MOCK_ARG (0x11ff8), MOCK_ARG_PTR_CONTAINS (&expected2, sizeof (expected2)),
		MOCK_ARG (sizeof (expected2)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected3),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected3, sizeof (expected3)),
		MOCK_ARG (sizeof (expected3)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc5;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected4),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected4, sizeof (expected4)),
		MOCK_ARG (sizeof (expected4)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Force the next write to wrap again. */
	manager.store_addr = 0x10ff8;
	manager.nv_state = 0xffc7;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_upgrade_to_sector2 (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0xff82, 0xff82, 0xff82, 0};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end) , 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10003),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[3], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_upgrade_to_sector2_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = 2 * 1024;
	uint16_t expected[4] = {0xff82, 0xff82, 0xff82, 0};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end) , 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10801),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10802),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10803),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[3], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_upgrade_to_sector1 (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};

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
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_upgrade_to_sector1_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xffff, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = 2 * 1024;
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11001),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[1], 1, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11002),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, &state[2], 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_upgrade_sector1_full (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t raw[4] = {0x4140, 0xff42, 0xffff, 0xffff};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint8_t *state = (uint8_t*) raw;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0xff80, 0xff80, 0xff80, 0};
	int i;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, raw, sizeof (raw), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end) , 2);

	for (i = 0x10000; i < 0x11000; i++) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(1));
		status |= mock_expect_output (&flash.mock, 1, &state[0], 1, 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(1));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_bit_errors (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0x2284, 0x12b5, 0x13b4, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0x12b4, 0x12b4, 0x12b4, 0};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10018), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_reserved_bits (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff8e, 0xff8e, 0xff8e, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xff0e;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_double_bit_error_fakes_blank (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffbf, 0xffff, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0xffbf, 0xffbf, 0xffbf, 0};

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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_triple_bit_error_fakes_blank (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xfffe};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0xffbf, 0xffbf, 0xffbf, 0};

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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_double_bit_error_fakes_blank_not_latest (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xffff, 0xffbf, 0xffff, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0x12b4, 0x12b4, 0x12b4, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint16_t expected[4] = {0x12b4, 0x12b4, 0x12b4, 0};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_flash_different (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff83, 0xff83, 0xff83, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_bit_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff82, 0xff82, 0xff83, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff82, 0xffc2, 0xff82, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff82, 0xffc2, 0xff82, 0};
	uint32_t bytes = 2 * 1024;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10808),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x11000), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector2 (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff82, 0xffc2, 0xff82, 0};
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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector2_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t bad_state[4] = {0xff82, 0xffc2, 0xff82, 0};
	uint32_t bytes = 2 * 1024;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, bad_state, sizeof (bad_state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (state),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (&state, sizeof (state)),
		MOCK_ARG (sizeof (state)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_null (CuTest *test)
{
	int status;

	TEST_START;

	status = state_manager_store_non_volatile_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);
}

static void state_manager_test_store_non_volatile_state_write_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xfffe;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_incomplete_write (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected) - 1,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xfffe;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_INCOMPLETE_WRITE, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10008), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_sector1_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end , sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11008), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, expected, sizeof (expected), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Call again with the same state to trigger the erase again. */
	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_sector2_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t state3[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff83, 0xff83, 0xff83, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10010),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state3, sizeof (state3), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10018), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG(sizeof (expected)));

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x11000));

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10018),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, expected, sizeof (expected), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Call again with the same state to trigger the erase again. */
	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_none_blank (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state1[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t state2[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t expected[4] = {0xff83, 0xff83, 0xff83, 0};
	int i;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);

	status = 0;
	for (i = 0x10000; i < 0x11ff8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state1, sizeof (state1), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11ff8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state2, sizeof (state2), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc3;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_last_entry_second_sector_not_blank (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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

	for (i = 0x10000; i < 0x10ff8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10ff8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10ff8), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_last_entry_second_sector_not_blank_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
	uint32_t bytes = 2 * 1024;
	int i;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x10800; i < 0x10ff8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10ff8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10ff8), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_last_entry_first_sector_not_blank (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int i;

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
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x11000; i < 0x11ff8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11ff8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x11ff8), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_last_entry_first_sector_not_blank_sector_not_4k (
	CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xff81, 0xff81, 0xff81, 0};
	uint32_t bytes = 2 * 1024;
	int i;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	for (i = 0x11000; i < 0x117f8; i += 8) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (i),
			MOCK_ARG_NOT_NULL, MOCK_ARG(8));
		status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x117f8),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (&manager, &flash.base, 0x10800);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10800, 0x800);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xffc1;

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_BLANK, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Retry */
	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x117f8), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_same_state_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG(8));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_store_non_volatile_state_after_blocking (CuTest *test)
{
	struct flash_mock flash;
	struct state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
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

	status = state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (expected),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	manager.nv_state = 0xfffe;

	state_manager_block_non_volatile_state_storage (&manager, true);
	state_manager_block_non_volatile_state_storage (&manager, false);

	status = state_manager_store_non_volatile_state (&manager);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager);
}

static void state_manager_test_block_non_volatile_state_storage_null (CuTest *test)
{
	TEST_START;

	state_manager_block_non_volatile_state_storage (NULL, true);
}


TEST_SUITE_START (state_manager);

TEST (state_manager_test_init);
TEST (state_manager_test_init_sector_not_4k);
TEST (state_manager_test_init_find_latest_state);
TEST (state_manager_test_init_find_latest_state_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_second_sector);
TEST (state_manager_test_init_find_latest_state_second_sector_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_last_byte);
TEST (state_manager_test_init_find_latest_state_last_byte_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_first_sector_low_state_count);
TEST (state_manager_test_init_not_block_aligned);
TEST (state_manager_test_init_not_block_aligned_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_updated_format);
TEST (state_manager_test_init_find_latest_state_updated_format_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_second_sector_updated_format);
TEST (state_manager_test_init_find_latest_state_second_sector_updated_format_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_last_entry_updated_format);
TEST (state_manager_test_init_find_latest_state_last_entry_updated_format_sector_not_4k);
TEST (state_manager_test_init_find_latest_state_updated_format_bit_errors);
TEST (state_manager_test_init_find_latest_state_updated_format_bit_error_on_type);
TEST (state_manager_test_init_find_latest_state_updated_format_double_bit_error_fakes_blank);
TEST (state_manager_test_init_find_latest_state_updated_format_triple_bit_error_fakes_blank);
TEST (state_manager_test_init_find_latest_state_updated_format_bit_error_both_types_cleared);
TEST (state_manager_test_init_find_latest_state_both_formats);
TEST (state_manager_test_init_find_latest_state_both_formats_second_sector);
TEST (state_manager_test_init_null);
TEST (state_manager_test_init_sector_size_error);
TEST (state_manager_test_init_not_sector_aligned);
TEST (state_manager_test_init_not_sector_aligned_sector_not_4k);
TEST (state_manager_test_init_read_error_first_sector);
TEST (state_manager_test_init_read_error_second_sector);
TEST (state_manager_test_init_find_state_read_error);
TEST (state_manager_test_init_find_state_read_second_sector_error);
TEST (state_manager_test_init_find_state_low_state_count_read_error);
TEST (state_manager_test_init_find_state_low_state_count_second_sector_read_error);
TEST (state_manager_test_init_find_state_updated_format_read_error);
TEST (state_manager_test_init_find_state_updated_format_second_sector_read_error);
TEST (state_manager_test_init_erase_error);
TEST (state_manager_test_release_null);
TEST (state_manager_test_store_non_volatile_state);
TEST (state_manager_test_store_non_volatile_state_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_not_first);
TEST (state_manager_test_store_non_volatile_state_not_first_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_second_sector);
TEST (state_manager_test_store_non_volatile_state_second_sector_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_same_state);
TEST (state_manager_test_store_non_volatile_state_store_change_twice);
TEST (state_manager_test_store_non_volatile_state_multiple_changes);
TEST (state_manager_test_store_non_volatile_state_wrap_to_second_sector);
TEST (state_manager_test_store_non_volatile_state_wrap_to_second_sector_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_wrap_to_first_sector);
TEST (state_manager_test_store_non_volatile_state_wrap_to_first_sector_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_write_twice_second_not_blank);
TEST (state_manager_test_store_non_volatile_state_write_twice_first_not_blank);
TEST (state_manager_test_store_non_volatile_state_wrap_to_second_then_first);
TEST (state_manager_test_store_non_volatile_state_wrap_to_first_then_second);
TEST (state_manager_test_store_non_volatile_state_upgrade_to_sector2);
TEST (state_manager_test_store_non_volatile_state_upgrade_to_sector2_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_upgrade_to_sector1);
TEST (state_manager_test_store_non_volatile_state_upgrade_to_sector1_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_upgrade_sector1_full);
TEST (state_manager_test_store_non_volatile_state_bit_errors);
TEST (state_manager_test_store_non_volatile_state_reserved_bits);
TEST (state_manager_test_store_non_volatile_state_double_bit_error_fakes_blank);
TEST (state_manager_test_store_non_volatile_state_triple_bit_error_fakes_blank);
TEST (state_manager_test_store_non_volatile_state_double_bit_error_fakes_blank_not_latest);
TEST (state_manager_test_store_non_volatile_state_same_state_flash_different);
TEST (state_manager_test_store_non_volatile_state_same_state_bit_error);
TEST (state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker);
TEST (state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector2);
TEST (state_manager_test_store_non_volatile_state_same_state_bit_error_on_entry_marker_sector2_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_null);
TEST (state_manager_test_store_non_volatile_state_write_error);
TEST (state_manager_test_store_non_volatile_state_incomplete_write);
TEST (state_manager_test_store_non_volatile_state_sector1_erase_error);
TEST (state_manager_test_store_non_volatile_state_sector2_erase_error);
TEST (state_manager_test_store_non_volatile_state_none_blank);
TEST (state_manager_test_store_non_volatile_state_last_entry_second_sector_not_blank);
TEST (state_manager_test_store_non_volatile_state_last_entry_second_sector_not_blank_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_last_entry_first_sector_not_blank);
TEST (state_manager_test_store_non_volatile_state_last_entry_first_sector_not_blank_sector_not_4k);
TEST (state_manager_test_store_non_volatile_state_same_state_read_error);
TEST (state_manager_test_store_non_volatile_state_after_blocking);
TEST (state_manager_test_block_non_volatile_state_storage_null);

TEST_SUITE_END;
