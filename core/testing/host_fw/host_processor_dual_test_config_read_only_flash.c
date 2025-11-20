// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "host_processor_dual_testing.h"
#include "testing.h"
#include "recovery/recovery_image_header.h"


TEST_SUITE_LABEL ("host_processor_dual");


/**
 * Set up expectations for filtered bypass mode in dual flash configurations.
 *
 * @param host Testing dependencies.
 * @param ro_cs The RO CS used for bypass mode.  The value in the filter will be opposite this.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
int host_processor_dual_testing_expect_filtered_bypass_mode (
	struct host_processor_dual_testing *host, spi_filter_cs ro_cs)
{
	int status;

	status = mock_expect (&host->filter.mock, host->filter.base.clear_filter_rw_regions,
		&host->filter, 0);
	status |= mock_expect (&host->filter.mock, host->filter.base.set_filter_rw_region,
		&host->filter, 0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));

	status |= mock_expect (&host->filter.mock, host->filter.base.set_ro_cs, &host->filter, 0,
		MOCK_ARG (!ro_cs));

	status |= mock_expect (&host->observer.mock, host->observer.base.on_bypass_mode,
		&host->observer, 0);

	return status;
}


/*******************
 * Test cases
 *******************/

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_no_current_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_current_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_FLASH_CONFIG_UNSUPPORTED, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_current_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_FLASH_CONFIG_UNSUPPORTED, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_no_next_cs_change (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, false);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	/* It should not be possible to have an override in active mode. */
	status = host_state_manager_override_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, false, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1_next_cs0 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;
	spi_filter_cs next_ro = SPI_FILTER_CS_0;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1_next_cs1 (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_no_apply_next_cs_change (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_apply_next_cs_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, &apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_apply_next_cs_run_time (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, &apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_apply_next_cs_por_only (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, &apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_apply_next_cs_all (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_ALL;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host_state_manager_save_read_only_activation_events (&host.host_state,
		HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, &apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_static_init (CuTest *test)
{
	struct host_processor_dual_testing host = {
		.test = host_processor_dual_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base,
			&host.recovery_manager.base)
	};
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME;

	TEST_START;

	host_processor_dual_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro,
		&apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_static_init_pulse_reset (CuTest *test)
{
	struct host_processor_dual_testing host = {
		.test = host_processor_dual_static_init_pulse_reset (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base,
			&host.recovery_manager.base, 100)
	};
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_0;
	spi_filter_cs next_ro = SPI_FILTER_CS_1;
	enum host_read_only_activation apply_next_cs = HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY;

	TEST_START;

	host_processor_dual_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, &next_ro,
		&apply_next_cs);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_null (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (NULL, NULL, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_invalid_current_cs (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = (spi_filter_cs) 2;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_invalid_next_cs (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs next_ro = (spi_filter_cs) 2;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, &next_ro, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_invalid_apply_next_cs (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	enum host_read_only_activation apply_next_cs = (enum host_read_only_activation) 4;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = host.test.base.config_read_only_flash (&host.test.base, NULL, NULL, &apply_next_cs);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, false,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_rot_access_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, HOST_FLASH_MGR_ROT_ACCESS_FAILED, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_host_access_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= host_processor_dual_testing_expect_filtered_bypass_mode (&host, SPI_FILTER_CS_1);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, HOST_FLASH_MGR_HOST_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_filter_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_config_read_only_flash_cs_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;
	spi_filter_cs current_ro = SPI_FILTER_CS_1;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = host_state_manager_save_read_only_flash_nv_config (&host.host_state, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (&host.host_state, false);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_clear_read_only_flash_override (&host.host_state);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter,
		SPI_FILTER_SET_RO_FAILED, MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter,
		SPI_FILTER_SET_RO_FAILED, MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter,
		SPI_FILTER_SET_RO_FAILED, MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter,
		SPI_FILTER_SET_RO_FAILED, MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_rw_region, &host.filter,
		0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG (0xffff0000));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_ro_cs, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_CS_0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.config_read_only_flash (&host.test.base, &current_ro, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, true, host_state_manager_is_bypass_mode (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_1,
		host_state_manager_get_read_only_flash (&host.host_state));
	CuAssertIntEquals (test, SPI_FILTER_CS_0,
		host_state_manager_get_read_only_flash_nv_config (&host.host_state));
	CuAssertIntEquals (test, true,
		host_state_manager_has_read_only_flash_override (&host.host_state));
	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host.host_state));
	CuAssertIntEquals (test, HOST_READ_ONLY_ACTIVATE_ON_ALL,
		host_state_manager_get_read_only_activation_events (&host.host_state));

	host_processor_dual_testing_validate_and_release (test, &host);
}


// *INDENT-OFF*
TEST_SUITE_START (host_processor_dual_config_read_only_flash);

TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_no_current_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_current_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_current_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_override_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_override_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_no_override_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs0_override_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_no_override_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_no_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_active_nv_cs1_override_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs0_no_override_current_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs0_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1_next_cs0);
TEST (host_processor_dual_test_config_read_only_flash_bypass_nv_cs1_no_override_current_cs1_next_cs1);
TEST (host_processor_dual_test_config_read_only_flash_no_apply_next_cs_change);
TEST (host_processor_dual_test_config_read_only_flash_apply_next_cs_reset);
TEST (host_processor_dual_test_config_read_only_flash_apply_next_cs_run_time);
TEST (host_processor_dual_test_config_read_only_flash_apply_next_cs_por_only);
TEST (host_processor_dual_test_config_read_only_flash_apply_next_cs_all);
TEST (host_processor_dual_test_config_read_only_flash_static_init);
TEST (host_processor_dual_test_config_read_only_flash_static_init_pulse_reset);
TEST (host_processor_dual_test_config_read_only_flash_null);
TEST (host_processor_dual_test_config_read_only_flash_invalid_current_cs);
TEST (host_processor_dual_test_config_read_only_flash_invalid_next_cs);
TEST (host_processor_dual_test_config_read_only_flash_invalid_apply_next_cs);
TEST (host_processor_dual_test_config_read_only_flash_rot_access_error);
TEST (host_processor_dual_test_config_read_only_flash_host_access_error);
TEST (host_processor_dual_test_config_read_only_flash_filter_error);
TEST (host_processor_dual_test_config_read_only_flash_cs_error);

TEST_SUITE_END;
// *INDENT-ON*
