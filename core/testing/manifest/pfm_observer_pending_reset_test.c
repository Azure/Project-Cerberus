// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_observer_pending_reset.h"
#include "manifest/manifest_logging.h"
#include "testing/mock/host_fw/host_control_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("pfm_observer_pending_reset");


/*******************
 * Test cases
 *******************/

static void pfm_observer_pending_reset_test_init (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, observer.base.on_pfm_verified);
	CuAssertPtrEquals (test, NULL, observer.base.on_pfm_activated);
	CuAssertPtrNotNull (test, observer.base.on_clear_active);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_init_null (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (NULL, &control.base);
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = pfm_observer_pending_reset_init (&observer, NULL);
	CuAssertIntEquals (test, PFM_OBSERVER_INVALID_ARGUMENT, status);

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);
}

static void pfm_observer_pending_reset_test_release_null (CuTest *test)
{
	TEST_START;

	pfm_observer_pending_reset_release (NULL);
}

static void pfm_observer_pending_reset_test_on_pfm_verified (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	struct logging_mock logger;
	int status;
	struct pfm_mock pfm;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;
	observer.base.on_pfm_verified (&observer.base, &pfm.base);
	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_on_pfm_verified_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	struct logging_mock logger;
	int status;
	struct pfm_mock pfm;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_PENDING_RESET_FAIL,
		.arg1 = HOST_CONTROL_HOLD_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_init (&pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;
	observer.base.on_pfm_verified (&observer.base, &pfm.base);
	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_mock_validate_and_release (&pfm);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_on_clear_active (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	struct logging_mock logger;
	int status;

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control, 0,
		MOCK_ARG (true));
	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;
	observer.base.on_clear_active (&observer.base);
	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}

static void pfm_observer_pending_reset_test_on_clear_active_control_error (CuTest *test)
{
	struct host_control_mock control;
	struct pfm_observer_pending_reset observer;
	struct logging_mock logger;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_PENDING_RESET_FAIL,
		.arg1 = HOST_CONTROL_HOLD_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	status = host_control_mock_init (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&logger);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_pending_reset_init (&observer, &control.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&control.mock, control.base.hold_processor_in_reset, &control,
		HOST_CONTROL_HOLD_RESET_FAILED, MOCK_ARG (true));

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	debug_log = &logger.base;
	observer.base.on_clear_active (&observer.base);
	debug_log = NULL;

	status = host_control_mock_validate_and_release (&control);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&logger);
	CuAssertIntEquals (test, 0, status);

	pfm_observer_pending_reset_release (&observer);
}


TEST_SUITE_START (pfm_observer_pending_reset);

TEST (pfm_observer_pending_reset_test_init);
TEST (pfm_observer_pending_reset_test_init_null);
TEST (pfm_observer_pending_reset_test_release_null);
TEST (pfm_observer_pending_reset_test_on_pfm_verified);
TEST (pfm_observer_pending_reset_test_on_pfm_verified_control_error);
TEST (pfm_observer_pending_reset_test_on_clear_active);
TEST (pfm_observer_pending_reset_test_on_clear_active_control_error);

TEST_SUITE_END;
