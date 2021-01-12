// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_processor_dual_testing.h"


static const char *SUITE = "host_processor_dual";


/*******************
 * Test cases
 *******************/

static void host_processor_dual_test_recover_active_read_write_data_no_pfm (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the flash, the
	 * filter must have not been operating in bypass mode.  If run-time validation was successful
	 * while bypass mode was active, the filter would be activated with no prevalidated state being
	 * stored. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_and_pfm (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the R/W flash and
	 * the pending PFM, the PFM dirty bit would also have been cleared.  If the PFM dirty bit was
	 * later set, the prevalidation state would no longer indicate both flash and PFM validation
	 * has already been completed.
	 *
	 * There also may not be a pending PFM. */
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the flash, the
	 * filter must have not been operating in bypass mode.  If run-time validation was successful
	 * while bypass mode was active, the filter would be activated with no prevalidated state being
	 * stored. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the flash, the
	 * filter must have not been operating in bypass mode.  If run-time validation was successful
	 * while bypass mode was active, the filter would be activated with no prevalidated state being
	 * stored. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the flash, the
	 * filter must have not been operating in bypass mode.  If run-time validation was successful
	 * while bypass mode was active, the filter would be activated with no prevalidated state being
	 * stored.
	 *
	 * There also may not be a pending PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_ACTIVE_RW_DATA, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_null (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host.test.base.recover_active_read_write_data (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_rot_access_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_ROT_ACCESS_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_rot_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_ROT_ACCESS_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_host_access_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_host_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_get_rw_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, HOST_FLASH_MGR_GET_RW_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_GET_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_restore_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_RESTORE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_get_rw_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, HOST_FLASH_MGR_GET_RW_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_GET_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_restore_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_RESTORE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_get_rw_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, HOST_FLASH_MGR_GET_RW_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_GET_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_restore_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_RESTORE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_get_rw_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, HOST_FLASH_MGR_GET_RW_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_GET_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_restore_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.get_flash_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 2, &rw_list, sizeof (rw_list), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 2, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.restore_flash_read_write_regions, &host.flash_mgr,
		HOST_FLASH_MGR_RESTORE_RW_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.free_read_write_regions, &host.pfm, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.recover_active_read_write_data (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_RESTORE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}


CuSuite* get_host_processor_dual_recover_active_read_write_data_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, host_processor_dual_test_recover_active_read_write_data_no_pfm);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_checked);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_checked_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_not_dirty_pulse_reset);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_and_pfm);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_and_pfm_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_pulse_reset);
	SUITE_ADD_TEST (suite, host_processor_dual_test_recover_active_read_write_data_null);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_rot_access_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_rot_access_error_pulse_reset);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_host_access_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_host_access_error_pulse_reset);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_get_rw_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_restore_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_get_rw_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_prevalidated_flash_restore_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_get_rw_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_restore_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_get_rw_error);
	SUITE_ADD_TEST (suite,
		host_processor_dual_test_recover_active_read_write_data_active_pfm_dirty_checked_prevalidated_flash_and_pfm_restore_error);

	return suite;
}
