// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_state_observer_dirty_reset.h"
#include "host_fw/host_state_manager.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"


TEST_SUITE_LABEL ("host_state_observer_dirty_reset");


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash The flash device to initialize for state.
 */
void host_state_observer_dirty_reset_testing_init_host_state (CuTest *test,
	struct host_state_manager *state, struct flash_mock *flash)
{
	int status;
	uint32_t sector_size = 0x1000;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (8));
	status |= mock_expect_output (&flash->mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void host_state_observer_dirty_reset_test_init (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, observer.base.on_active_pfm);
	CuAssertPtrEquals (test, NULL, observer.base.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.base.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.base.on_active_recovery_image);
	CuAssertPtrEquals (test, NULL, observer.base.on_pfm_dirty);
	CuAssertPtrEquals (test, NULL, observer.base.on_run_time_validation);
	CuAssertPtrEquals (test, NULL, observer.base.on_bypass_mode);
	CuAssertPtrEquals (test, NULL, observer.base.on_unsupported_flash);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);
}

static void host_state_observer_dirty_reset_test_init_null (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_dirty_reset_init (NULL, &control.base);
	CuAssertIntEquals (test, HOST_STATE_OBSERVER_INVALID_ARGUMENT, status);

	status = host_state_observer_dirty_reset_init (&observer, NULL);
	CuAssertIntEquals (test, HOST_STATE_OBSERVER_INVALID_ARGUMENT, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void host_state_observer_dirty_reset_test_release_null (CuTest *test)
{
	TEST_START;

	host_state_observer_dirty_reset_release (NULL);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_dirty (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_testing_init_host_state (test, &state, &flash);

	host_state_manager_save_inactive_dirty (&state, true);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_inactive_dirty (&observer.base, &state);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&state);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_not_dirty (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_testing_init_host_state (test, &state, &flash);

	host_state_manager_save_inactive_dirty (&state, false);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	observer.base.on_inactive_dirty (&observer.base, &state);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&state);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	int status;
	struct flash_mock flash;
	struct host_state_manager state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_testing_init_host_state (test, &state, &flash);

	host_state_manager_save_inactive_dirty (&state, true);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	observer.base.on_inactive_dirty (&observer.base, &state);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&state);
}


TEST_SUITE_START (host_state_observer_dirty_reset);

TEST (host_state_observer_dirty_reset_test_init);
TEST (host_state_observer_dirty_reset_test_init_null);
TEST (host_state_observer_dirty_reset_test_release_null);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_dirty);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_not_dirty);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_control_error);

TEST_SUITE_END;
