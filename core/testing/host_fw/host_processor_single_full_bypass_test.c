// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_processor_single_full_bypass.h"
#include "host_fw/host_fw_util.h"
#include "host_fw/host_state_manager.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/host_fw/host_flash_manager_single_mock.h"
#include "testing/mock/host_fw/host_processor_observer_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/host_fw/host_processor_single_testing.h"


TEST_SUITE_LABEL ("host_processor_single_full_bypass");


/**
 * Dependencies for testing.
 */
struct host_processor_single_full_bypass_testing {
	HASH_TESTING_ENGINE hash;							/**< Hash engine for API arguments. */
	RSA_TESTING_ENGINE rsa;								/**< RSA engine for API arguments. */
	struct flash_master_mock flash_mock_state;			/**< Flash mock for host state information. */
	struct spi_flash_state flash_context;				/**< Host state flash context. */
	struct spi_flash flash_state;						/**< Host state flash. */
	struct host_state_manager host_state;				/**< Host state manager. */
	struct spi_filter_interface_mock filter;			/**< Mock for the SPI filter. */
	struct host_flash_manager_single_mock flash_mgr;	/**< Mock for flash management. */
	struct host_control_mock control;					/**< Mock for host control. */
	struct pfm_manager_mock pfm_mgr;					/**< Mock for PFM management. */
	struct pfm_mock pfm;								/**< Mock for a valid PFM. */
	struct pfm_mock pfm_next;							/**< Mock for a valid pending PFM. */
	struct host_processor_observer_mock observer;		/**< Mock for host notifications. */
	struct host_processor_filtered test;				/**< Host instance being tested. */
};


/**
 * Initialize the host processor dependencies.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
static void host_processor_single_full_bypass_testing_init_dependencies (CuTest *test,
	struct host_processor_single_full_bypass_testing *host)
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

	status = host_flash_manager_single_mock_init (&host->flash_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_mock_init (&host->observer);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host->host_state, &host->flash_mock_state,
		&host->flash_state, &host->flash_context);
}

/**
 * Initialize a host processor.
 *
 * @param test The testing framework.
 * @param host The testing components to initialize.
 */
static void host_processor_single_full_bypass_testing_init (CuTest *test,
	struct host_processor_single_full_bypass_testing *host)
{
	int status;

	host_processor_single_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_single_full_bypass_init (&host->test, &host->control.base,
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
static void host_processor_single_full_bypass_testing_init_pulse_reset (CuTest *test,
	struct host_processor_single_full_bypass_testing *host)
{
	int status;

	host_processor_single_full_bypass_testing_init_dependencies (test, host);

	status = host_processor_single_full_bypass_init_pulse_reset (&host->test, &host->control.base,
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
static void host_processor_single_full_bypass_testing_validate_and_release (CuTest *test,
	struct host_processor_single_full_bypass_testing *host)
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

	status = host_flash_manager_single_mock_validate_and_release (&host->flash_mgr);
	CuAssertIntEquals (test, 0, status);

	status = host_processor_observer_mock_validate_and_release (&host->observer);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_full_bypass_release (&host->test);

	host_state_manager_release (&host->host_state);
	spi_flash_release (&host->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&host->hash);
	RSA_TESTING_ENGINE_RELEASE (&host->rsa);
}


/*******************
 * Test cases
 *******************/

static void host_processor_single_full_bypass_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
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

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_single_full_bypass_init (&host, &control.base, &flash_mgr.base,
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

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
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

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_single_full_bypass_init (NULL, &control.base, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init (&host, NULL, &flash_mgr.base,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init (&host, &control.base, NULL,
		&host_state, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init (&host, &control.base, &flash_mgr.base,
		NULL, &filter.base, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init (&host, &control.base, &flash_mgr.base,
		&host_state, NULL, &pfm_mgr.base, NULL);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init (&host, &control.base, &flash_mgr.base,
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

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_pulse_reset (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
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

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
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

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_full_bypass_release (&host);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_pulse_reset_null (CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
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

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_pulse_reset (NULL, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, NULL,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
		NULL, &host_state, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
		&flash_mgr.base, NULL, &filter.base, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
		&flash_mgr.base, &host_state, NULL, &pfm_mgr.base, NULL, 100);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
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

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_init_pulse_reset_invalid_pulse_width (
	CuTest *test)
{
	struct flash_master_mock flash_mock_state;
	struct spi_flash_state flash_context;
	struct spi_flash flash_state;
	struct host_state_manager host_state;
	struct spi_filter_interface_mock filter;
	struct host_flash_manager_single_mock flash_mgr;
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

	status = host_flash_manager_single_mock_init (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_processor_single_testing_init_host_state (test, &host_state, &flash_mock_state,
		&flash_state, &flash_context);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
		&flash_mgr.base, &host_state, &filter.base, &pfm_mgr.base, NULL, 0);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	status = host_processor_single_full_bypass_init_pulse_reset (&host, &control.base,
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

	status = host_flash_manager_single_mock_validate_and_release (&flash_mgr);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash_state);
}

static void host_processor_single_full_bypass_test_release_null (CuTest *test)
{
	TEST_START;

	host_processor_single_full_bypass_release (NULL);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_cs1 (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_no_observer (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_bypass (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_checked (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_bypass (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_checked (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	host_state_manager_set_pfm_dirty (&host.host_state, false);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_checked_bypass (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_pulse_reset (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_pulse_reset (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_no_pfm_filter_error (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.power_on_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_bypass_enable_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		SPI_FILTER_SET_FILTER_MODE_FAILED, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));
	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter,
		0, MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

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

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_flash_supported (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_no_pfm_filter_error (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.soft_reset (&host.test.base, &host.hash.base, &host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_rot_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init_pulse_reset (test, &host);

	status = host_state_manager_save_inactive_dirty (&host.host_state, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_FLASH_MGR_ROT_ACCESS_FAILED, MOCK_ARG (&host.control));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_soft_reset, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_no_pfm (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_no_pfm_filter_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.run_time_verification (&host.test.base, &host.hash.base,
		&host.rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, false, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.base.clear_all_manifests,
		&host.pfm_mgr, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_flash_dirty_state,
		&host.filter, 0);

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) NULL);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.pfm.mock, host.pfm.base.base.is_empty, &host.pfm, 1);

	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.free_pfm, &host.pfm_mgr, 0,
		MOCK_ARG (&host.pfm));
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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	status |= mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest_filter_error (
	CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_active_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm);
	status |= mock_expect (&host.pfm_mgr.mock, host.pfm_mgr.base.get_pending_pfm, &host.pfm_mgr,
		(intptr_t) &host.pfm_next);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

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

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_bypass_mode_ro_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_bypass_mode_ro_flash_cs1 (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_bypass_mode_rw_flash (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_bypass_mode_rw_flash_cs0 (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

	status = host_state_manager_save_read_only_flash (&host.host_state, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.filter.mock, host.filter.base.set_filter_mode, &host.filter, 0,
		MOCK_ARG (SPI_FILTER_FLASH_BYPASS_CS0));

	status |= mock_expect (&host.observer.mock, host.observer.base.on_bypass_mode, &host.observer,
		0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_get_read_only_flash (&host.host_state);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}

static void host_processor_single_full_bypass_test_bypass_mode_enable_error (CuTest *test)
{
	struct host_processor_single_full_bypass_testing host;
	int status;

	TEST_START;

	host_processor_single_full_bypass_testing_init (test, &host);

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
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.bypass_mode (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&host.host_state);
	CuAssertIntEquals (test, true, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_single_full_bypass_testing_validate_and_release (test, &host);
}


TEST_SUITE_START (host_processor_single_full_bypass);

TEST (host_processor_single_full_bypass_test_init);
TEST (host_processor_single_full_bypass_test_init_null);
TEST (host_processor_single_full_bypass_test_init_pulse_reset);
TEST (host_processor_single_full_bypass_test_init_pulse_reset_null);
TEST (host_processor_single_full_bypass_test_init_pulse_reset_invalid_pulse_width);
TEST (host_processor_single_full_bypass_test_release_null);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_cs1);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_no_observer);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_bypass);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_checked);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_checked_bypass);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_bypass);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_checked);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_dirty_checked_bypass);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_pulse_reset);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_validation_fail);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_hash_validation_fail);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_not_dirty_unknown_version);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_validation_fail);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_hash_validation_fail);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_unknown_version);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_power_on_reset_no_pfm_filter_error);
TEST (host_processor_single_full_bypass_test_power_on_reset_pending_pfm_no_active_dirty_bypass_enable_error);
TEST (host_processor_single_full_bypass_test_soft_reset_rot_access_error_pulse_reset);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm);
TEST (host_processor_single_full_bypass_test_soft_reset_no_pfm_filter_error);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_no_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_soft_reset_pending_pfm_with_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_single_full_bypass_test_run_time_verification_no_pfm);
TEST (host_processor_single_full_bypass_test_run_time_verification_no_pfm_filter_error);
TEST (host_processor_single_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_run_time_verification_pending_pfm_no_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_single_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest);
TEST (host_processor_single_full_bypass_test_run_time_verification_pending_pfm_with_active_not_dirty_empty_manifest_filter_error);
TEST (host_processor_single_full_bypass_test_bypass_mode_ro_flash);
TEST (host_processor_single_full_bypass_test_bypass_mode_ro_flash_cs1);
TEST (host_processor_single_full_bypass_test_bypass_mode_rw_flash);
TEST (host_processor_single_full_bypass_test_bypass_mode_rw_flash_cs0);
TEST (host_processor_single_full_bypass_test_bypass_mode_enable_error);

TEST_SUITE_END;
