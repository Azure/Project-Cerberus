// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_fw_util.h"
#include "host_fw/host_processor_dual_full_bypass.h"
#include "host_fw/host_processor_dual_full_bypass_static.h"
#include "testing/host_fw/host_processor_dual_full_bypass_testing.h"
#include "testing/host_fw/host_processor_dual_testing.h"


TEST_SUITE_LABEL ("host_processor_dual_full_bypass");


/**
 * Initialize the host processor dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_full_bypass_testing_init_dependencies (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&host->hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&host->rsa);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_init (&host->filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_init (&host->control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (&host->pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&host->pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&host->pfm_next);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_dual_mock_init (&host->flash_mgr);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_init (&host->recovery_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_init (&host->image);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_mock_init (&host->observer);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&host->logger);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host->host_state, &host->host_state_context,
		&host->flash_mock_state, &host->flash_state, &host->flash_context);
}

/**
 * Release testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_processor_dual_full_bypass_testing_release_dependencies (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	status = flash_master_mock_validate_and_release (&host->flash_mock_state);
	status |= spi_filter_interface_mock_validate_and_release (&host->filter);
	status |= host_control_mock_validate_and_release (&host->control);
	status |= pfm_manager_mock_validate_and_release (&host->pfm_mgr);
	status |= pfm_mock_validate_and_release (&host->pfm);
	status |= pfm_mock_validate_and_release (&host->pfm_next);
	status |= host_flash_manager_dual_mock_validate_and_release (&host->flash_mgr);
	status |= recovery_image_manager_mock_validate_and_release (&host->recovery_manager);
	status |= recovery_image_mock_validate_and_release (&host->image);
	status |= host_processor_observer_mock_validate_and_release (&host->observer);
	status |= logging_mock_validate_and_release (&host->logger);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host->host_state);
	spi_flash_release (&host->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&host->hash);
	RSA_TESTING_ENGINE_RELEASE (&host->rsa);
}

/**
 * Initialize a host processor.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
static void host_processor_dual_full_bypass_testing_init (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	host_processor_dual_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_dual_full_bypass_init (&host->test, &host->state, &host->control.base,
		&host->flash_mgr.base, &host->host_state, &host->filter.base, &host->pfm_mgr.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor that pulses the reset.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
static void host_processor_dual_full_bypass_testing_init_pulse_reset (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	host_processor_dual_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host->test, &host->state,
		&host->control.base, &host->flash_mgr.base, &host->host_state, &host->filter.base,
		&host->pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor that resets the host flash.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_full_bypass_testing_init_reset_flash (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	host_processor_dual_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_dual_full_bypass_init_reset_flash (&host->test, &host->state,
		&host->control.base, &host->flash_mgr.base, &host->host_state, &host->filter.base,
		&host->pfm_mgr.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor that resets the host flash and pulses the reset.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_full_bypass_testing_init_reset_flash_pulse_reset (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	host_processor_dual_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_dual_full_bypass_init_reset_flash_pulse_reset (&host->test,
		&host->state, &host->control.base, &host->flash_mgr.base, &host->host_state,
		&host->filter.base, &host->pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a statically initialized host processor for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_full_bypass_testing_init_static (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	int status;

	host_processor_dual_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_filtered_init_state (&host->test);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param host The testing components to release.
 */
void host_processor_dual_full_bypass_testing_validate_and_release (CuTest *test,
	struct host_processor_dual_full_bypass_testing *host)
{
	host_processor_dual_full_bypass_release (&host->test);
	host_processor_dual_full_bypass_testing_release_dependencies (test, host);
}


/*******************
 * Test cases
 *******************/

static void host_processor_dual_full_bypass_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
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

	status = host_flash_manager_dual_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_dual_full_bypass_init (&host, &state, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
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

	status = host_flash_manager_dual_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_full_bypass_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
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

	status = host_flash_manager_dual_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_dual_full_bypass_init (NULL, &state, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, NULL, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, &state, NULL, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, &state, &control.base, NULL, &host_state,
		&filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, &state, &control.base, &flash_mgr.base,
		NULL, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, &state, &control.base, &flash_mgr.base,
		&host_state, NULL, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init (&host, &state, &control.base, &flash_mgr.base,
		&host_state, &filter.base, NULL, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_dual_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_full_bypass_test_init_pulse_reset (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
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

	status = host_flash_manager_dual_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
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

	status = host_flash_manager_dual_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_full_bypass_test_init_pulse_reset_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
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

	status = host_flash_manager_dual_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_dual_full_bypass_init_pulse_reset (NULL, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, NULL, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, NULL, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base, NULL,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, NULL, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, &host_state, NULL, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, NULL, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_dual_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_full_bypass_test_init_pulse_reset_invalid_pulse_width (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager_state host_state_context;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
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

	status = host_flash_manager_dual_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_init_host_state (test, &host_state, &host_state_context,
		&flash_mock_state, &flash_state, &flash_context);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 0);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_full_bypass_init_pulse_reset (&host, &state, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, -1);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_dual_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_full_bypass_test_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
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

	host_processor_dual_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&host.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.test.base));

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_static_init_null (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	struct host_processor_filtered null_state =
		host_processor_dual_full_bypass_static_init ((struct host_processor_filtered_state*) NULL,
		&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
		&host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_control =
		host_processor_dual_full_bypass_static_init (&host.state, NULL, &host.flash_mgr.base,
		&host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_flash =
		host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
		(struct host_flash_manager_dual*) NULL, &host.host_state, &host.filter.base,
		&host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_host_state =
		host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
		&host.flash_mgr.base, NULL, &host.filter.base, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_filter =
		host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, NULL, &host.pfm_mgr.base, NULL);

	struct host_processor_filtered null_pfm =
		host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, NULL, NULL);

	TEST_START;

	host_processor_dual_full_bypass_testing_init_dependencies (test, &host);

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

	host_processor_dual_full_bypass_testing_release_dependencies (test, &host);
}

static void host_processor_dual_full_bypass_test_static_init_pulse_reset (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
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

	host_processor_dual_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&host.test);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, host_processor_get_port (&host.test.base));

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_static_init_pulse_reset_null (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	struct host_processor_filtered null_state =
		host_processor_dual_full_bypass_static_init_pulse_reset (
		(struct host_processor_filtered_state*) NULL, &host.control.base, &host.flash_mgr.base,
		&host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_control =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, NULL,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_flash =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, &host.control.base,
		(struct host_flash_manager_dual*) NULL, &host.host_state, &host.filter.base,
		&host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_host_state =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, &host.control.base,
		&host.flash_mgr.base, NULL, &host.filter.base, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_filter =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, NULL, &host.pfm_mgr.base, NULL, 100);

	struct host_processor_filtered null_pfm =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, NULL, NULL, 100);

	TEST_START;

	host_processor_dual_full_bypass_testing_init_dependencies (test, &host);

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

	host_processor_dual_full_bypass_testing_release_dependencies (test, &host);
}

static void host_processor_dual_full_bypass_test_static_init_pulse_reset_invalid_pulse_width (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	struct host_processor_filtered negative =
		host_processor_dual_full_bypass_static_init_pulse_reset (&host.state, &host.control.base,
		&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL, -1);

	TEST_START;

	host_processor_dual_full_bypass_testing_init_dependencies (test, &host);

	status = host_processor_filtered_init_state (&negative);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_full_bypass_testing_release_dependencies (test, &host);
}

static void host_processor_dual_full_bypass_test_release_null (CuTest *test)
{
	TEST_START;

	host_processor_dual_full_bypass_release (NULL);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_cs1 (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_no_observer (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_bypass (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_checked (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_checked_bypass (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_bypass (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_checked (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_pulse_reset (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR (&host.pfm), MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG_PTR (&host.pfm), MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG_PTR (&host.pfm),
		MOCK_ARG_PTR (NULL), MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR (&host.pfm), MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_BAD_IMAGE_HASH, MOCK_ARG_PTR (&host.pfm), MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, HOST_FW_UTIL_UNSUPPORTED_VERSION, MOCK_ARG_PTR (&host.pfm),
		MOCK_ARG_PTR (NULL), MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true),
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_static_init_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_power_on_reset_no_pfm_filter_error (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_bypass_enable_error
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_type, &host.flash_mgr, 0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.validate_read_only_flash,
		&host.flash_mgr, RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR (&host.pfm), MOCK_ARG_PTR (NULL),
		MOCK_ARG_PTR (&host.hash), MOCK_ARG_PTR (&host.rsa), MOCK_ARG (true), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_soft_reset_rot_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_pulse_reset (test, &host);

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_ROT_ACCESS_FAILED, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_soft_reset_no_pfm (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_soft_reset_no_pfm_filter_error (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_filter_error
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_filter_error
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_soft_reset_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_soft_reset_static_init_pulse_reset (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

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

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_run_time_verification_no_pfm (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_run_time_verification_no_pfm_filter_error (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest_filter_error
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest_filter_error
(
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm_next));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.pfm_next.mock, host.pfm_next.base.base.is_empty, &host.pfm_next,
		1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm_next));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE,
		host_state_manager_get_run_time_validation (&host.host_state));

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_run_time_verification_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_run_time_verification_static_init_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass_cs1 (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_flash_rollback_active_pfm_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_inactive_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass_enable_error (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_flash_rollback_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_flash_rollback_static_init_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		MOCK_RETURN_PTR (&host.pfm));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG_PTR (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.flash_rollback (&host.test.base, &host.hash.base, &host.rsa.base, false,
		false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_ro_flash (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_ro_flash_cs1 (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_rw_flash (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS1));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_rw_flash_cs0 (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_static_init_pulse_reset (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_bypass_mode_enable_error (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG_PTR (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_apply_recovery_image_static_init (CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base,
			&host.recovery_manager.base)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

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

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_dual_full_bypass_test_apply_recovery_image_static_init_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, &host.recovery_manager.base, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

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

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_apply_recovery_image_static_init_no_recovery_manager (
	CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init (&host.state, &host.control.base,
			&host.flash_mgr.base, &host.host_state, &host.filter.base, &host.pfm_mgr.base, NULL)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}

static void
host_processor_dual_full_bypass_test_apply_recovery_image_static_init_no_recovery_manager_pulse_reset
	(CuTest *test)
{
	struct host_processor_dual_full_bypass_testing host = {
		.test = host_processor_dual_full_bypass_static_init_pulse_reset (&host.state,
			&host.control.base, &host.flash_mgr.base, &host.host_state, &host.filter.base,
			&host.pfm_mgr.base, NULL, 100)
	};
	int status;

	TEST_START;

	host_processor_dual_full_bypass_testing_init_static (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_full_bypass_testing_validate_and_release (test, &host);
}


// *INDENT-OFF*
TEST_SUITE_START (host_processor_dual_full_bypass);

TEST (host_processor_dual_full_bypass_test_init);
TEST (host_processor_dual_full_bypass_test_init_null);
TEST (host_processor_dual_full_bypass_test_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_init_pulse_reset_null);
TEST (host_processor_dual_full_bypass_test_init_pulse_reset_invalid_pulse_width);
TEST (host_processor_dual_full_bypass_test_static_init);
TEST (host_processor_dual_full_bypass_test_static_init_null);
TEST (host_processor_dual_full_bypass_test_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_static_init_pulse_reset_null);
TEST (host_processor_dual_full_bypass_test_static_init_pulse_reset_invalid_pulse_width);
TEST (host_processor_dual_full_bypass_test_release_null);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_cs1);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_no_observer);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_bypass);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_checked);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_checked_bypass);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_bypass);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_checked);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_dirty_checked_bypass);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_pulse_reset);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_power_on_reset_static_init);
TEST (host_processor_dual_full_bypass_test_power_on_reset_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_power_on_reset_no_pfm_filter_error);
TEST (host_processor_dual_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_bypass_enable_error);
TEST (host_processor_dual_full_bypass_test_soft_reset_rot_access_error_pulse_reset);
TEST (host_processor_dual_full_bypass_test_soft_reset_no_pfm);
TEST (host_processor_dual_full_bypass_test_soft_reset_no_pfm_filter_error);
TEST (host_processor_dual_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_dual_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_dual_full_bypass_test_soft_reset_static_init);
TEST (host_processor_dual_full_bypass_test_soft_reset_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_run_time_verification_no_pfm);
TEST (host_processor_dual_full_bypass_test_run_time_verification_no_pfm_filter_error);
TEST (host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_dual_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_dual_full_bypass_test_run_time_verification_static_init);
TEST (host_processor_dual_full_bypass_test_run_time_verification_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass);
TEST (host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass_cs1);
TEST (host_processor_dual_full_bypass_test_flash_rollback_active_pfm_dirty_bypass);
TEST (host_processor_dual_full_bypass_test_flash_rollback_active_pfm_not_dirty_bypass_enable_error);
TEST (host_processor_dual_full_bypass_test_flash_rollback_static_init);
TEST (host_processor_dual_full_bypass_test_flash_rollback_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_bypass_mode_ro_flash);
TEST (host_processor_dual_full_bypass_test_bypass_mode_ro_flash_cs1);
TEST (host_processor_dual_full_bypass_test_bypass_mode_rw_flash);
TEST (host_processor_dual_full_bypass_test_bypass_mode_rw_flash_cs0);
TEST (host_processor_dual_full_bypass_test_bypass_mode_static_init);
TEST (host_processor_dual_full_bypass_test_bypass_mode_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_bypass_mode_enable_error);
TEST (host_processor_dual_full_bypass_test_apply_recovery_image_static_init);
TEST (host_processor_dual_full_bypass_test_apply_recovery_image_static_init_pulse_reset);
TEST (host_processor_dual_full_bypass_test_apply_recovery_image_static_init_no_recovery_manager);
TEST (host_processor_dual_full_bypass_test_apply_recovery_image_static_init_no_recovery_manager_pulse_reset);

TEST_SUITE_END;
// *INDENT-ON*
