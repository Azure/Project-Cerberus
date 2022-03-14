// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_processor_dual_testing.h"


TEST_SUITE_LABEL ("host_processor_dual");


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
static void host_processor_dual_testing_init_dependencies (CuTest *test,
	struct host_processor_dual_testing *host)
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

	host_processor_dual_testing_init_host_state (test, &host->host_state, &host->flash_mock_state,
		&host->flash_state, &host->flash_context);
}

/**
 * Initialize a host processor for testing.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_testing_init (CuTest *test,
	struct host_processor_dual_testing *host)
{
	int status;

	host_processor_dual_testing_init_dependencies (test, host);

	status = host_processor_dual_init (&host->test, &host->control.base, &host->flash_mgr.base,
		&host->host_state, &host->filter.base, &host->pfm_mgr.base, &host->recovery_manager.base);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor for testing, configured to pulse the reset line.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_testing_init_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host)
{
	int status;

	host_processor_dual_testing_init_dependencies (test, host);

	status = host_processor_dual_init_pulse_reset (&host->test, &host->control.base,
		&host->flash_mgr.base, &host->host_state, &host->filter.base, &host->pfm_mgr.base,
		&host->recovery_manager.base, 100);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor without a recovery image manager.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_testing_init_no_recovery (CuTest *test,
	struct host_processor_dual_testing *host)
{
	int status;

	host_processor_dual_testing_init_dependencies (test, host);

	status = host_processor_dual_init (&host->test, &host->control.base, &host->flash_mgr.base,
		&host->host_state, &host->filter.base, &host->pfm_mgr.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_add_observer (&host->test.base, &host->observer.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a host processor without a recovery image manager, configured to pulse the reset line.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
void host_processor_dual_testing_init_no_recovery_pulse_reset (CuTest *test,
	struct host_processor_dual_testing *host)
{
	int status;

	host_processor_dual_testing_init_dependencies (test, host);

	status = host_processor_dual_init_pulse_reset (&host->test, &host->control.base,
		&host->flash_mgr.base, &host->host_state, &host->filter.base, &host->pfm_mgr.base, NULL,
		100);
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
void host_processor_dual_testing_validate_and_release (CuTest *test,
	struct host_processor_dual_testing *host)
{
	int status;

	status = flash_master_mock_validate_and_release (&host->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&host->filter);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&host->control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (&host->pfm_mgr);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&host->pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&host->pfm_next);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_manager_dual_mock_validate_and_release (&host->flash_mgr);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_manager_mock_validate_and_release (&host->recovery_manager);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_mock_validate_and_release (&host->image);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_mock_validate_and_release (&host->observer);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_release (&host->test);

	host_state_manager_release (&host->host_state);
	spi_flash_release (&host->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&host->hash);
	RSA_TESTING_ENGINE_RELEASE (&host->rsa);
}

/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash_mock The mock for the flash state storage.
 * @param flash The flash device to initialize for state.
 * @param flash_state Context for the flash device.
 */
void host_processor_dual_testing_init_host_state (CuTest *test, struct host_state_manager *state,
	struct flash_master_mock *flash_mock, struct spi_flash *flash,
	struct spi_flash_state *flash_state)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (flash, flash_state, &flash_mock->base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (flash_mock, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void host_processor_dual_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
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

	host_processor_dual_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_dual_init (&host, &control.base, &flash_mgr.base, &host_state,
		&filter.base, &pfm_mgr.base, NULL);
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

	host_processor_dual_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
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

	host_processor_dual_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_dual_init (NULL, &control.base, &flash_mgr.base, &host_state,
		&filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init (&host, NULL, &flash_mgr.base, &host_state,
		&filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init (&host, &control.base, NULL, &host_state,
		&filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init (&host, &control.base, &flash_mgr.base, NULL,
		&filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init (&host, &control.base, &flash_mgr.base, &host_state,
		NULL, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init (&host, &control.base, &flash_mgr.base, &host_state,
		&filter.base, NULL, NULL);
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

static void host_processor_dual_test_init_pulse_reset (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
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

	host_processor_dual_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
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

	host_processor_dual_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_dual_test_init_pulse_reset_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
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

	host_processor_dual_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_dual_init_pulse_reset (NULL, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, NULL, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, NULL,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		NULL, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		&host_state, NULL, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		&host_state, &filter.base, NULL, NULL, 100);
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

static void host_processor_dual_test_init_pulse_reset_invalid_pulse_width (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_dual_mock flash_mgr;
	struct host_control_mock control;
	struct pfm_manager_mock pfm_mgr;
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

	host_processor_dual_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, 0);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_dual_init_pulse_reset (&host, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL, -1);
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

static void host_processor_dual_test_release_null (CuTest *test)
{
	TEST_START;

	host_processor_dual_release (NULL);
}

static void host_processor_dual_test_needs_config_recovery (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.host_has_flash_access,
		&host.flash_mgr, 1, MOCK_ARG(&host.control));
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.needs_config_recovery (&host.test.base);
	CuAssertIntEquals (test, 0, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_needs_config_recovery_no_host_access (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.host_has_flash_access,
		&host.flash_mgr, 0, MOCK_ARG(&host.control));
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.needs_config_recovery (&host.test.base);
	CuAssertIntEquals (test, 1, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_needs_config_recovery_null (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host.test.base.needs_config_recovery (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_needs_config_recovery_check_access_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.host_has_flash_access,
		&host.flash_mgr, HOST_FLASH_MGR_CHECK_ACCESS_FAILED, MOCK_ARG(&host.control));
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.needs_config_recovery (&host.test.base);
	CuAssertIntEquals (test, HOST_FLASH_MGR_CHECK_ACCESS_FAILED, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_checked_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_and_pfm (
	CuTest *test)
{
	/* This scenario should not be possible since there is no pending PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible since there is no pending PFM.
	 *
	 * This scenario is doubly infeasible due to the inability to have a prevalidated state stored
	 * while the filter is operating in bypass mode. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_and_pfm (
	CuTest *test)
{
	/* This scenario should not be possible since there is no pending PFM. */

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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible since there is no pending PFM.
	 *
	 * This scenario is doubly infeasible due to the inability to have a prevalidated state stored
	 * while the filter is operating in bypass mode. */

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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty (
	CuTest *test)
{
	/* This scenario should not be possible since the host will be in bypass mode without an active
	 * PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_checked (
	CuTest *test)
{
	/* This scenario should not be possible since the host will be in bypass mode without an active
	 * PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty (
	CuTest *test)
{
	/* This scenario should not be possible since the host will be in bypass mode without an active
	 * PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_checked (
	CuTest *test)
{
	/* This scenario should not be possible since the host will be in bypass mode without an active
	 * PFM. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_checked_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_NONE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_bypass (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the R/W flash and
	 * the pending PFM, the PFM dirty bit would also have been cleared.  If the PFM dirty bit was
	 * later set, the prevalidation state would no longer indicate both flash and PFM validation
	 * has already been completed. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm_bypass (
	CuTest *test)
{
	/* This scenario should not be possible.  In order to have already validated the R/W flash and
	 * the pending PFM, the PFM dirty bit would also have been cleared.  If the PFM dirty bit was
	 * later set, the prevalidation state would no longer indicate both flash and PFM validation
	 * has already been completed.
	 *
	 * This scenario is doubly infeasible due to the inability to have a prevalidated state stored
	 * while the filter is operating in bypass mode. */

	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&host.host_state,
		HOST_STATE_PREVALIDATED_FLASH_AND_PFM);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_PFM_AND_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_ACTIVATE_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_bypass (
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

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm (
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
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_ACTIVATE_PFM_AND_UPDATE, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm_bypass (
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
	host_state_manager_set_pfm_dirty (&host.host_state, false);
	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG(&host.pfm_next));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.get_next_reset_verification_actions (&host.test.base);
	CuAssertIntEquals (test, HOST_PROCESSOR_ACTION_VERIFY_BYPASS_FLASH, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_get_next_reset_verification_actions_null (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host.test.base.get_next_reset_verification_actions (NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}


TEST_SUITE_START (host_processor_dual);

TEST (host_processor_dual_test_init);
TEST (host_processor_dual_test_init_null);
TEST (host_processor_dual_test_init_pulse_reset);
TEST (host_processor_dual_test_init_pulse_reset_null);
TEST (host_processor_dual_test_init_pulse_reset_invalid_pulse_width);
TEST (host_processor_dual_test_release_null);
TEST (host_processor_dual_test_needs_config_recovery);
TEST (host_processor_dual_test_needs_config_recovery_no_host_access);
TEST (host_processor_dual_test_needs_config_recovery_null);
TEST (host_processor_dual_test_needs_config_recovery_check_access_error);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_no_pfm_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_not_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_and_pfm);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_and_pfm);
TEST (host_processor_dual_test_get_next_reset_verification_actions_active_pfm_dirty_checked_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_not_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_no_active_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_not_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm);
TEST (host_processor_dual_test_get_next_reset_verification_actions_pending_pfm_with_active_dirty_checked_prevalidated_flash_and_pfm_bypass);
TEST (host_processor_dual_test_get_next_reset_verification_actions_null);

TEST_SUITE_END;
