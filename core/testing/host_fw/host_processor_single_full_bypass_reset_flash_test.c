// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_logging.h"
#include "host_fw/host_processor_single_full_bypass.h"
#include "testing/host_fw/host_processor_single_full_bypass_testing.h"
#include "testing/host_fw/host_processor_single_testing.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("host_processor_single_full_bypass");


/*******************
 * Test cases
 *******************/

static void host_processor_single_full_bypass_test_init_reset_flash (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
	struct host_processor_filtered_state state;
	struct host_processor_filtered host;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.base));

	CuAssertPtrNotNull (test, host.base.power_on_reset);
	CuAssertPtrNotNull (test, host.base.soft_reset);
	CuAssertPtrNotNull (test, host.base.run_time_verification);
	CuAssertPtrNotNull (test, host.base.flash_rollback);
	CuAssertPtrNotNull (test, host.base.recover_active_read_write_data);
	CuAssertPtrNotNull (test, host.base.get_next_reset_verification_actions);
	CuAssertPtrNotNull (test, host.base.needs_config_recovery);
	CuAssertPtrNotNull (test, host.base.apply_recovery_image);
	CuAssertPtrNotNull (test, host.base.bypass_mode);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_reset_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
	struct host_processor_filtered_state state;
	struct host_processor_filtered host;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_reset_flash (NULL, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, NULL, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, NULL,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, &control.base, NULL,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, &control.base,
		&flash_mgr.base, NULL, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, &control.base,
		&flash_mgr.base, &host_state, NULL, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_reset_flash_pulse_reset (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
	struct host_processor_filtered_state state;
	struct host_processor_filtered host;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.base));

	CuAssertPtrNotNull (test, host.base.power_on_reset);
	CuAssertPtrNotNull (test, host.base.soft_reset);
	CuAssertPtrNotNull (test, host.base.run_time_verification);
	CuAssertPtrNotNull (test, host.base.flash_rollback);
	CuAssertPtrNotNull (test, host.base.recover_active_read_write_data);
	CuAssertPtrNotNull (test, host.base.get_next_reset_verification_actions);
	CuAssertPtrNotNull (test, host.base.needs_config_recovery);
	CuAssertPtrNotNull (test, host.base.apply_recovery_image);
	CuAssertPtrNotNull (test, host.base.bypass_mode);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_reset_flash_pulse_reset_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
	struct host_processor_filtered_state state;
	struct host_processor_filtered host;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (NULL, &state,
		&control.base, &flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, NULL,
		&control.base, &flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state, NULL,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, NULL, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, NULL, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, &host_state, NULL, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, &host_state, &filter.base, NULL, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_reset_flash_pulse_reset_invalid_pulse_width
(
	CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
	struct host_processor_filtered_state state;
	struct host_processor_filtered host;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 0);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_reset_flash_pulse_reset (&host, &state,
		&control.base, &flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, -1);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_static_init_reset_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, host.test.base.power_on_reset);
	CuAssertPtrNotNull (test, host.test.base.soft_reset);
	CuAssertPtrNotNull (test, host.test.base.run_time_verification);
	CuAssertPtrNotNull (test, host.test.base.flash_rollback);
	CuAssertPtrNotNull (test, host.test.base.recover_active_read_write_data);
	CuAssertPtrNotNull (test, host.test.base.get_next_reset_verification_actions);
	CuAssertPtrNotNull (test, host.test.base.needs_config_recovery);
	CuAssertPtrNotNull (test, host.test.base.apply_recovery_image);
	CuAssertPtrNotNull (test, host.test.base.bypass_mode);

	host_processor_single_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&host.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.test.base));

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_static_init_reset_flash_null (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	struct host_processor_filtered null_state =
		host_processor_single_full_bypass_static_init_reset_flash (
		(struct host_processor_filtered_state*) NULL, &host.control.base, &host.flash_mgr.base,
		&host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_control =
		host_processor_single_full_bypass_static_init_reset_flash (&host.state, NULL,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_flash =
		host_processor_single_full_bypass_static_init_reset_flash (&host.state, &host.control.base,
		(struct host_flash_manager_single*) NULL, &host.host_state, &host.filter.base,
		&host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_host_state =
		host_processor_single_full_bypass_static_init_reset_flash (&host.state, &host.control.base,
		&host.flash_mgr.base, NULL, &host.filter.base, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_filter =
		host_processor_single_full_bypass_static_init_reset_flash (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, NULL, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_pfm =
		host_processor_single_full_bypass_static_init_reset_flash (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, NULL, NULL);

	TEST_START;

	host_processor_single_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_control);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_flash);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_filter);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_pfm);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_single_full_bypass_testing_release_dependencies (test, &host);
}

static void host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, host.test.base.power_on_reset);
	CuAssertPtrNotNull (test, host.test.base.soft_reset);
	CuAssertPtrNotNull (test, host.test.base.run_time_verification);
	CuAssertPtrNotNull (test, host.test.base.flash_rollback);
	CuAssertPtrNotNull (test, host.test.base.recover_active_read_write_data);
	CuAssertPtrNotNull (test, host.test.base.get_next_reset_verification_actions);
	CuAssertPtrNotNull (test, host.test.base.needs_config_recovery);
	CuAssertPtrNotNull (test, host.test.base.apply_recovery_image);
	CuAssertPtrNotNull (test, host.test.base.bypass_mode);

	host_processor_single_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&host.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.test.base));

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset_null (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	struct host_processor_filtered null_state =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (
		(struct host_processor_filtered_state*) NULL, &host.control.base, &host.flash_mgr.base,
		&host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_control =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state, NULL,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_flash =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
		&host.control.base, (struct host_flash_manager_single*) NULL, &host.host_state,
		&host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_host_state =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
		&host.control.base, &host.flash_mgr.base, NULL, &host.filter.base, &host.pfm_mgr.base, NULL,
		100);

	struct host_processor_filtered null_filter =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
		&host.control.base, &host.flash_mgr.base, &host.host_state, NULL, &host.pfm_mgr.base, NULL,
		100);

	struct host_processor_filtered null_pfm =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
		&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base, NULL, NULL,
		100);

	TEST_START;

	host_processor_single_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_control);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_flash);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_host_state);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_filter);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_filtered_init_state (&null_pfm);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_single_full_bypass_testing_release_dependencies (test, &host);
}

static void
host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset_invalid_pulse_width (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	struct host_processor_filtered negative =
		host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
		&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
		&host.pfm_mgr.base, NULL, -1);

	TEST_START;

	host_processor_single_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&negative);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_single_full_bypass_testing_release_dependencies (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_bypass_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_static_init_reset_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL)
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_static_init_reset_flash_pulse_reset (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_null_reset_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = host.test.base.soft_reset (NULL, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.soft_reset (&host.test.base, NULL, &host.rsa.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_not_supported_reset_flash
(
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = SPI_FLASH_RESET_NOT_SUPPORTED
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, SPI_FLASH_RESET_NOT_SUPPORTED);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_error_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = FLASH_MASTER_XFER_FAILED
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, FLASH_MASTER_XFER_FAILED);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, FLASH_MASTER_XFER_FAILED);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, FLASH_MASTER_XFER_FAILED);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_error_succeed_on_retry_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_fail = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = FLASH_MASTER_XFER_FAILED
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, FLASH_MASTER_XFER_FAILED);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_fail, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_fail)));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_soft_reset_rot_access_error_pulse_reset_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash_pulse_reset (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_ROT_ACCESS_FAILED, status);

	debug_log = NULL;

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_filter_error_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_filter_error = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_BYPASS_MODE_ERROR,
		.arg1 = 0,
		.arg2 = SPI_FILTER_SET_FILTER_MODE_FAILED
	};
	struct debug_log_entry_info entry_filter_pass = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_BYPASS_MODE_ERROR,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);

	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_filter_error,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_filter_error)));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_filter_pass,
		LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED), MOCK_ARG (sizeof (entry_filter_pass)));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_reset_flash
	(CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_clr_pfms = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_CLEAR_PFMS,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_clr_pfms, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_clr_pfms)));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_reset_flash
	(CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_FLASH_RESET,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_clr_pfms = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_CLEAR_PFMS,
		.arg1 = 0,
		.arg2 = 0
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_reset_flash (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.reset_flash,
		&host.flash_mgr, 0);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);
	status |= mock_expect (&host.logger.mock, host.logger.base.create_entry, &host.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_clr_pfms, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_clr_pfms)));

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	debug_log = &host.logger.base;

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, &host.recovery_manager.base)
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		MOCK_RETURN_PTR (&host.image.base));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, MOCK_RETURN_PTR (&host.flash_state));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG_PTR (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_pulse_reset (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, &host.recovery_manager.base, 100)
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		MOCK_RETURN_PTR (&host.image.base));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, MOCK_RETURN_PTR (&host.flash_state));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG_PTR (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_no_recovery_manager
	(CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_no_recovery_manager_pulse_reset
	(CuTest *test)
{
	struct host_processor_single_full_bypass_testing host = {
		.test = host_processor_single_full_bypass_static_init_reset_flash_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_static (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}


// *INDENT-OFF*
TEST_SUITE_START (host_processor_single_full_bypass_reset_flash);

TEST (host_processor_single_full_bypass_test_init_reset_flash);
TEST (host_processor_single_full_bypass_test_init_reset_flash_null);
TEST (host_processor_single_full_bypass_test_init_reset_flash_pulse_reset);
TEST (host_processor_single_full_bypass_test_init_reset_flash_pulse_reset_null);
TEST (host_processor_single_full_bypass_test_init_reset_flash_pulse_reset_invalid_pulse_width);
TEST (host_processor_single_full_bypass_test_static_init_reset_flash);
TEST (host_processor_single_full_bypass_test_static_init_reset_flash_null);
TEST (host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset);
TEST (host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset_null);
TEST (host_processor_single_full_bypass_test_static_init_reset_flash_pulse_reset_invalid_pulse_width);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_bypass_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_static_init_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_static_init_reset_flash_pulse_reset);
TEST (host_processor_single_full_bypass_test_soft_reset_null_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_not_supported_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_error_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_reset_error_succeed_on_retry_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_rot_access_error_pulse_reset_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_filter_error_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_reset_flash);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_reset_flash);
TEST (host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash);
TEST (host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_pulse_reset);
TEST (host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_no_recovery_manager);
TEST (host_processor_single_full_bypass_test_apply_recovery_image_static_init_reset_flash_no_recovery_manager_pulse_reset);


TEST_SUITE_END;
// *INDENT-ON*
