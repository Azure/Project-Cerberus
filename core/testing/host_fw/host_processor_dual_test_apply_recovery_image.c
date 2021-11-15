// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_processor_dual_testing.h"
#include "recovery/recovery_image_header.h"


TEST_SUITE_LABEL ("host_processor_dual");


/*******************
 * Test cases
 *******************/

static void host_processor_dual_test_apply_recovery_image (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_pulse_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_observer (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host_processor_remove_observer (&host.test.base, &host.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_bypass (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_reset_pulse_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, true);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_valid_image (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		((intptr_t) NULL));
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_RECOVERY_IMAGE, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_valid_image_pulse_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		((intptr_t) NULL));
	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_NO_RECOVERY_IMAGE, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_recovery_manager (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_no_recovery (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_no_recovery_manager_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_no_recovery_pulse_reset (test, &host);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_RECOVERY_UNSUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_unsupported_flash (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_unsupported_flash (&host.host_state, true);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_FLASH_NOT_SUPPORTED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_bypass_unsupported_flash (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	host_state_manager_set_bypass_mode (&host.host_state, true);
	host_state_manager_set_unsupported_flash (&host.host_state, true);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, true, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_null (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = host.test.base.apply_recovery_image (NULL, false);
	CuAssertIntEquals (test, HOST_PROCESSOR_INVALID_ARGUMENT, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (&host.control));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error_host_access_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, HOST_CONTROL_FLASH_ACCESS_FAILED, MOCK_ARG (&host.control));

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

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, HOST_CONTROL_FLASH_ACCESS_FAILED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_chip_erase_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_rx_xfer (&host.flash_mock_state, 0, &WIP_STATUS, 1,
	FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&host.flash_mock_state, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&host.flash_mock_state, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE(0xc7));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_chip_erase_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_rx_xfer (&host.flash_mock_state, 0, &WIP_STATUS, 1,
	FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&host.flash_mock_state, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&host.flash_mock_state, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE(0xc7));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_bad_image (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image,
		RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_bad_image_pulse_reset (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image,
		RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_clear_rw_region_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

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

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_clear_rw_region_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

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

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_spi_filter_config_error (CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_spi_filter_config_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

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

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_host_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_set_flash_for_host_access_error (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));

	status |= mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

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

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}

static void host_processor_dual_test_apply_recovery_image_set_flash_for_host_access_error_pulse_reset (
	CuTest *test)
{
	struct host_processor_dual_testing host;
	int status;

	TEST_START;

	host_processor_dual_testing_init_pulse_reset (test, &host);

	status = mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.get_active_recovery_image, &host.recovery_manager,
		(intptr_t) &host.image.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.set_flash_for_rot_access,
		&host.flash_mgr, 0, MOCK_ARG (&host.control));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&host.flash_mgr.mock, host.flash_mgr.base.base.get_read_only_flash,
		&host.flash_mgr, (intptr_t) &host.flash_state);

	status |= mock_expect (&host.observer.mock, host.observer.base.on_recovery, &host.observer, 0);

	status |= flash_master_mock_expect_chip_erase (&host.flash_mock_state);

	status |= mock_expect (&host.image.mock, host.image.base.apply_to_flash, &host.image, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&host.filter.mock, host.filter.base.clear_filter_rw_regions,
		&host.filter, 0);

	status |= mock_expect (&host.flash_mgr.mock,
		host.flash_mgr.base.base.config_spi_filter_flash_devices, &host.flash_mgr, 0);

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

	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (true));
	status |= mock_expect (&host.control.mock, host.control.base.hold_processor_in_reset,
		&host.control, 0, MOCK_ARG (false));

	status |= mock_expect (&host.recovery_manager.mock,
		host.recovery_manager.base.free_recovery_image, &host.recovery_manager, 0,
		MOCK_ARG (&host.image));

	CuAssertIntEquals (test, 0, status);

	status = host.test.base.apply_recovery_image (&host.test.base, false);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&host.host_state);
	CuAssertIntEquals (test, false, status);

	host_processor_dual_testing_validate_and_release (test, &host);
}


TEST_SUITE_START (host_processor_dual_apply_recovery_image);

TEST (host_processor_dual_test_apply_recovery_image);
TEST (host_processor_dual_test_apply_recovery_image_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_no_observer);
TEST (host_processor_dual_test_apply_recovery_image_bypass);
TEST (host_processor_dual_test_apply_recovery_image_no_reset);
TEST (host_processor_dual_test_apply_recovery_image_no_reset_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_no_valid_image);
TEST (host_processor_dual_test_apply_recovery_image_no_valid_image_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_no_recovery_manager);
TEST (host_processor_dual_test_apply_recovery_image_no_recovery_manager_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_unsupported_flash);
TEST (host_processor_dual_test_apply_recovery_image_bypass_unsupported_flash);
TEST (host_processor_dual_test_apply_recovery_image_null);
TEST (host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error);
TEST (host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_set_flash_for_rot_access_error_host_access_error);
TEST (host_processor_dual_test_apply_recovery_image_chip_erase_error);
TEST (host_processor_dual_test_apply_recovery_image_chip_erase_error_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_bad_image);
TEST (host_processor_dual_test_apply_recovery_image_bad_image_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_clear_rw_region_error);
TEST (host_processor_dual_test_apply_recovery_image_clear_rw_region_error_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_spi_filter_config_error);
TEST (host_processor_dual_test_apply_recovery_image_spi_filter_config_error_pulse_reset);
TEST (host_processor_dual_test_apply_recovery_image_set_flash_for_host_access_error);
TEST (host_processor_dual_test_apply_recovery_image_set_flash_for_host_access_error_pulse_reset);

TEST_SUITE_END;
