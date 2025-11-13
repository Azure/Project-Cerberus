// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_logging.h"
#include "host_fw/host_state_manager.h"
#include "host_fw/host_state_observer_dirty_reset.h"
#include "host_fw/host_state_observer_dirty_reset_static.h"
#include "testing/host_fw/host_state_manager_testing.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("host_state_observer_dirty_reset");


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
	CuAssertPtrNotNull (test, observer.base.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.base.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.base.on_read_only_activation_events);
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

static void host_state_observer_dirty_reset_test_static_init (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer =
		host_state_observer_dirty_reset_static_init (&control.base);
	int status;

	TEST_START;

	CuAssertPtrEquals (test, NULL, observer.base.on_active_pfm);
	CuAssertPtrNotNull (test, observer.base.on_read_only_flash);
	CuAssertPtrNotNull (test, observer.base.on_inactive_dirty);
	CuAssertPtrEquals (test, NULL, observer.base.on_read_only_activation_events);
	CuAssertPtrEquals (test, NULL, observer.base.on_active_recovery_image);
	CuAssertPtrEquals (test, NULL, observer.base.on_pfm_dirty);
	CuAssertPtrEquals (test, NULL, observer.base.on_run_time_validation);
	CuAssertPtrEquals (test, NULL, observer.base.on_bypass_mode);
	CuAssertPtrEquals (test, NULL, observer.base.on_unsupported_flash);

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);
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
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_inactive_dirty (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_not_dirty (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_save_inactive_dirty (&host_state, false);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_inactive_dirty (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_static_init (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer =
		host_state_observer_dirty_reset_static_init (&control.base);
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_save_inactive_dirty (&host_state, true);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_inactive_dirty (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_inactive_dirty_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_DIRTY_RESET_ERROR,
		.arg1 = HOST_CONTROL_HOLD_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_save_inactive_dirty (&host_state, true);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_inactive_dirty (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_read_only_flash_with_override (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_override_read_only_flash (&host_state, SPI_FILTER_CS_1);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_read_only_flash (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_read_only_flash_no_override (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_read_only_flash (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_read_only_flash_static_init (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer =
		host_state_observer_dirty_reset_static_init (&control.base);
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_override_read_only_flash (&host_state, SPI_FILTER_CS_1);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_read_only_flash (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}

static void host_state_observer_dirty_reset_test_on_read_only_flash_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct host_state_observer_dirty_reset observer;
	struct logging_mock log;
	int status;
	struct flash_mock flash;
	struct host_state_manager_state host_state_ctx;
	struct host_state_manager host_state;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_HOST_FW,
		.msg_index = HOST_LOGGING_DIRTY_RESET_ERROR,
		.arg1 = HOST_CONTROL_HOLD_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_testing_init_host_state (test, &host_state, &host_state_ctx, &flash, true);

	host_state_manager_override_read_only_flash (&host_state, SPI_FILTER_CS_1);

	status = host_state_observer_dirty_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));

	status |= mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	observer.base.on_read_only_flash (&observer.base, &host_state);

	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	status |= logging_mock_validate_and_release (&log);
	status |= flash_mock_validate_and_release (&flash);

	CuAssertIntEquals (test, 0, status);

	host_state_observer_dirty_reset_release (&observer);

	host_state_manager_release (&host_state);
}


// *INDENT-OFF*
TEST_SUITE_START (host_state_observer_dirty_reset);

TEST (host_state_observer_dirty_reset_test_init);
TEST (host_state_observer_dirty_reset_test_init_null);
TEST (host_state_observer_dirty_reset_test_static_init);
TEST (host_state_observer_dirty_reset_test_release_null);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_dirty);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_not_dirty);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_static_init);
TEST (host_state_observer_dirty_reset_test_on_inactive_dirty_control_error);
TEST (host_state_observer_dirty_reset_test_on_read_only_flash_with_override);
TEST (host_state_observer_dirty_reset_test_on_read_only_flash_no_override);
TEST (host_state_observer_dirty_reset_test_on_read_only_flash_static_init);
TEST (host_state_observer_dirty_reset_test_on_read_only_flash_control_error);

TEST_SUITE_END;
// *INDENT-ON*
