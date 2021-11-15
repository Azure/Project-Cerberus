// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/host_fw/host_processor_single_testing.h"


TEST_SUITE_LABEL ("host_processor_single");


/*******************
 * Test cases
 *******************/

static void host_processor_single_test_power_on_reset_no_pfm (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_cs1 (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_no_observer (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_checked_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_dirty_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_dirty_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_dirty_checked_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_multiple_fw (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_no_observer (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0,
		MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0,
		MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_multiple_fw (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_no_observer (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_and_pfm (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the R/W flash and
	 * the pending PFM, the PFM dirty bit would also have been cleared.  If the PFM dirty bit was
	 * later set, the prevalidation state would no longer indicate both flash and PFM validation
	 * has already been completed. */

	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the R/W flash and
	 * the pending PFM, the PFM dirty bit would also have been cleared.  If the PFM dirty bit was
	 * later set, the prevalidation state would no longer indicate both flash and PFM validation
	 * has already been completed. */

	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked_bypass (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_multiple_fw (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_no_observer (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_multiple_fw (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_no_observer (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_multiple_fw (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_no_observer (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_multiple_fw (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region[2];
	struct pfm_read_write rw_prop[2];
	struct pfm_read_write_regions rw_list[2];
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x400;
	rw_region[1].length = 0x100;

	rw_prop[0].on_failure = PFM_RW_DO_NOTHING;
	rw_prop[1].on_failure = PFM_RW_DO_NOTHING;

	rw_list[0].regions = &rw_region[0];
	rw_list[0].properties = &rw_prop[0];
	rw_list[0].count = 1;

	rw_list[1].regions = &rw_region[1];
	rw_list[1].properties = &rw_prop[1];
	rw_list[1].count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = rw_list;
	rw_host.count = 2;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (2), MOCK_ARG (0x400), MOCK_ARG (0x500));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_no_observer (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_bypass_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state, HOST_STATE_PREVALIDATED_FLASH);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

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

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_BAD_IMAGE_HASH, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_BAD_IMAGE_HASH, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_blank_fail (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, FLASH_UTIL_UNEXPECTED_VALUE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_BAD_IMAGE_HASH, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_blank_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_blank_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_BAD_IMAGE_HASH, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_blank_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, FLASH_UTIL_UNEXPECTED_VALUE, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, FLASH_UTIL_UNEXPECTED_VALUE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_unknown_version (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG (&host.pfm),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_unsupported_flash (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_unsupported_flash (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_null (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host.test.base.power_on_reset (NULL, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.power_on_reset (&host.test.base, NULL, &host.rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_unsupported_device (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_UNSUPPORTED_DEVICE, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_incompatible_spi_master (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_no_device (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_NO_DEVICE, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_no_4byte_addr_commands (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_NO_4BYTE_CMDS, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_NO_4BYTE_CMDS, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_4byte_addr_incompatible (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_unknown_quad_enable (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_rot_access_large_device (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, SPI_FLASH_SFDP_LARGE_DEVICE, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_LARGE_DEVICE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_TYPE_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_TYPE_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_TYPE_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_unsupported_vendor (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_unsupported_device (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_mismatched_vendor (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_MISMATCH_VENDOR);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_VENDOR, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_mismatched_devices (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_MISMATCH_DEVICE);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_DEVICE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_mismatched_sizes (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_MISMATCH_SIZES);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_SIZES, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_flash_type_mismatched_addr_modes (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr,
		HOST_FLASH_MGR_MISMATCH_ADDR_MODE);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_MISMATCH_ADDR_MODE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_host_access_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_dirty_clear_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, SPI_FILTER_CLEAR_DIRTY_FAILED);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_filter_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_no_pfm_cs_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RO_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_config_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_not_dirty_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_swap_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_active_pfm_dirty_filter_error (CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RO_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm,
		MANIFEST_CHECK_EMPTY_FAILED);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_init_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr,
		HOST_FLASH_MGR_INIT_PROTECT_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr,
		HOST_FLASH_MGR_INIT_PROTECT_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr,
		HOST_FLASH_MGR_INIT_PROTECT_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr,
		HOST_FLASH_MGR_INIT_PROTECT_FAILED, MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.initialize_flash_protection, &host.flash_mgr, 0,
		MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_filter_bypass_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_cs_bypass_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_clear_manifest_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_clear_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, SPI_FILTER_CLEAR_DIRTY_FAILED);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_cs_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_NO_MEMORY, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RO_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_active_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_NO_MEMORY, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm), MOCK_ARG (NULL),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RO_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_config_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.activate_pending_manifest,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_config_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr,
		HOST_FLASH_MGR_CONFIG_FILTER_FAILED);
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RO_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (NULL), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG (false),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (NULL), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG (false), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 5, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 5, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_NO_MEMORY, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_NO_MEMORY, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_active_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_NO_MEMORY, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_NO_MEMORY, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_error_and_active_validation_fail (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_fail_and_active_validation_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash),
		MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_VALIDATE_RW_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		MANIFEST_CHECK_EMPTY_FAILED);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_swap_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (&host.pfm_mgr));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (&host.pfm_mgr));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (&host.pfm_mgr));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (&host.pfm_mgr));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		SPI_FILTER_SET_RW_FAILED, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		SPI_FILTER_SET_RW_FAILED, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		SPI_FILTER_SET_RW_FAILED, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		SPI_FILTER_SET_RW_FAILED, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_filter_unsupported_rw_region (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm_next.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm_next), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);
	status |= mock_expect_share_save_arg (&host.flash_mgr.mock, 0, &host.pfm_next.mock, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		SPI_FILTER_UNSUPPORTED_RW_REGION, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (&host.pfm_mgr));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in PFM manager.

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_swap_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, HOST_FLASH_MGR_SWAP_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;
	struct flash_region rw_region;
	struct pfm_read_write rw_prop;
	struct pfm_read_write_regions rw_list;
	struct host_flash_manager_rw_regions rw_host;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_prop.on_failure = PFM_RW_DO_NOTHING;

	rw_list.regions = &rw_region;
	rw_list.properties = &rw_prop;
	rw_list.count = 1;

	rw_host.pfm = &host.pfm.base;
	rw_host.writable = &rw_list;
	rw_host.count = 1;

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, HOST_FLASH_MGR_VALIDATE_RW_FAILED, MOCK_ARG (&host.pfm_next),
		MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_write_flash,
		&host.flash_mgr, 0, MOCK_ARG (&host.pfm), MOCK_ARG (&host.hash), MOCK_ARG (&host.rsa),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&host.flash_mgr.mock, 3, &rw_host, sizeof (rw_host), -1);
	status |= mock_expect_save_arg (&host.flash_mgr.mock, 3, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0x200), MOCK_ARG (0x300));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.swap_flash_devices,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_active_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.free_read_write_regions,
		&host.flash_mgr, 0, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);	// State changes in flash manager.

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_clear_manifest_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, MANIFEST_MANAGER_CLEAR_ALL_FAILED);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_CLEAR_ALL_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_clear_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, SPI_FILTER_CLEAR_DIRTY_FAILED);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, SPI_FILTER_CLEAR_RW_FAILED);
	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}

static void host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_cs_error (
	CuTest *test)
{
	struct host_processor_single_testing host;
	int status;

	TEST_START;

	host_processor_single_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region,
		&host.filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_SINGLE_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_testing_validate_and_release (test, &host);
}


TEST_SUITE_START (host_processor_single_power_on_reset);

TEST (host_processor_single_test_power_on_reset_no_pfm);
TEST (host_processor_single_test_power_on_reset_no_pfm_cs1);
TEST (host_processor_single_test_power_on_reset_no_pfm_no_observer);
TEST (host_processor_single_test_power_on_reset_no_pfm_bypass);
TEST (host_processor_single_test_power_on_reset_no_pfm_checked);
TEST (host_processor_single_test_power_on_reset_no_pfm_checked_bypass);
TEST (host_processor_single_test_power_on_reset_no_pfm_dirty);
TEST (host_processor_single_test_power_on_reset_no_pfm_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_no_pfm_dirty_checked);
TEST (host_processor_single_test_power_on_reset_no_pfm_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_checked);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_and_pfm);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_and_pfm);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_checked_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_checked_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_multiple_fw);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_no_observer);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_bypass_empty_manifest);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_bypass);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_blank_fail);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_blank_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_blank_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_unknown_version);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_hash_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_blank_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_unknown_version);
TEST (host_processor_single_test_power_on_reset_unsupported_flash);
TEST (host_processor_single_test_power_on_reset_null);
TEST (host_processor_single_test_power_on_reset_rot_access_error);
TEST (host_processor_single_test_power_on_reset_rot_access_unsupported_device);
TEST (host_processor_single_test_power_on_reset_rot_access_incompatible_spi_master);
TEST (host_processor_single_test_power_on_reset_rot_access_no_device);
TEST (host_processor_single_test_power_on_reset_rot_access_no_4byte_addr_commands);
TEST (host_processor_single_test_power_on_reset_rot_access_4byte_addr_incompatible);
TEST (host_processor_single_test_power_on_reset_rot_access_unknown_quad_enable);
TEST (host_processor_single_test_power_on_reset_rot_access_large_device);
TEST (host_processor_single_test_power_on_reset_flash_type_error);
TEST (host_processor_single_test_power_on_reset_flash_type_unsupported_vendor);
TEST (host_processor_single_test_power_on_reset_flash_type_unsupported_device);
TEST (host_processor_single_test_power_on_reset_flash_type_mismatched_vendor);
TEST (host_processor_single_test_power_on_reset_flash_type_mismatched_devices);
TEST (host_processor_single_test_power_on_reset_flash_type_mismatched_sizes);
TEST (host_processor_single_test_power_on_reset_flash_type_mismatched_addr_modes);
TEST (host_processor_single_test_power_on_reset_host_access_error);
TEST (host_processor_single_test_power_on_reset_no_pfm_dirty_clear_error);
TEST (host_processor_single_test_power_on_reset_no_pfm_filter_error);
TEST (host_processor_single_test_power_on_reset_no_pfm_cs_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_validation_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_config_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_not_dirty_filter_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_validation_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_swap_error);
TEST (host_processor_single_test_power_on_reset_active_pfm_dirty_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_init_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_filter_bypass_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_cs_bypass_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_clear_manifest_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_clear_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_no_active_dirty_empty_manifest_cs_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_checked_active_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_config_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_config_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_not_dirty_active_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_checked_active_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_error_and_active_validation_fail);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_validation_fail_and_active_validation_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_swap_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_filter_unsupported_rw_region);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_swap_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_active_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_clear_manifest_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_clear_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_filter_error);
TEST (host_processor_single_test_power_on_reset_pending_pfm_with_active_dirty_empty_manifest_cs_error);

TEST_SUITE_END;
