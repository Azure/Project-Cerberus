// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "logging/debug_log.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/real_time_clock_mock.h"


TEST_SUITE_LABEL ("debug_log");

/**
 * Helper function to setup the debug log for testing.
 *
 * @param test The test framework.
 * @param logger The logger instance to initialize and use as the debug log.
 * @param rtc The real time clock instance to initialize, if needed, and to use as the logger
 * timestamp.
 */
static void setup_debug_log_mock_test (CuTest *test, struct logging_mock *logger,
	struct real_time_clock_mock *rtc)
{
	int status;

	status = logging_mock_init (logger);
	CuAssertIntEquals (test, 0, status);

	if (rtc != NULL) {
		status = real_time_clock_mock_init (rtc);
		CuAssertIntEquals (test, 0, status);
	}

	debug_log = &logger->base;
	debug_timestamp = &rtc->base;
}

/**
 * Helper function to release the debug log and clear the global log.

 * @param test The test framework.
 * @param logger The logger instance to release.
 * @param rtc The real time clock instance to release, if used.
 */
static void complete_debug_log_mock_test (CuTest *test, struct logging_mock *logger,
	struct real_time_clock_mock *rtc)
{
	int status;

	if (rtc != NULL) {
		status = real_time_clock_mock_validate_and_release (rtc);
		CuAssertIntEquals (test, 0, status);
	}

	status = logging_mock_validate_and_release (logger);
	CuAssertIntEquals (test, 0, status);

	debug_timestamp = NULL;
	debug_log = NULL;
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void debug_log_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}

/*******************
 * Test cases
 *******************/

static void debug_log_test_create_entry (CuTest *test)
{
	struct logging_mock logger;
	struct real_time_clock_mock rtc;
	struct debug_log_entry_info entry = {
		.format = 1,
		.severity = 1,
		.component = 2,
		.msg_index = 3,
		.arg1 = 4,
		.arg2 = 5,
		.time = (uint64_t) -1
	};
	uint64_t timestamp = (uint64_t) -1;
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, &rtc);

	status = mock_expect (&rtc.mock, rtc.base.get_time, &rtc, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rtc.mock, 0, &timestamp, sizeof (timestamp), -1);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS (&entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = debug_log_create_entry (1, 2, 3, 4, 5);
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, &rtc);
}

static void debug_log_test_create_entry_no_log (CuTest *test)
{
	int status;

	TEST_START;

	debug_log = NULL;

	status = debug_log_create_entry (0, 0, 0, 0, 0);
	CuAssertIntEquals (test, LOGGING_NO_LOG_AVAILABLE, status);
}

static void debug_log_test_create_entry_no_timestamp (CuTest *test)
{
	struct logging_mock logger;
	struct debug_log_entry_info entry = {
		.format = 1,
		.severity = 1,
		.component = 2,
		.msg_index = 3,
		.arg1 = 4,
		.arg2 = 5,
		.time = 0
	};
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS (&entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = debug_log_create_entry (1, 2, 3, 4, 5);
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_create_entry_invalid_severity (CuTest *test)
{
	struct logging_mock logger;
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = debug_log_create_entry (DEBUG_LOG_NUM_SEVERITY, 2, 3, 4, 5);
	CuAssertIntEquals (test, LOGGING_UNSUPPORTED_SEVERITY, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_create_entry_timestamp_error (CuTest *test)
{
	struct logging_mock logger;
	struct real_time_clock_mock rtc;
	struct debug_log_entry_info entry = {
		.format = 1,
		.severity = 1,
		.component = 2,
		.msg_index = 3,
		.arg1 = 4,
		.arg2 = 5,
		.time = 0
	};
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, &rtc);

	status = mock_expect (&rtc.mock, rtc.base.get_time, &rtc, REAL_TIME_CLOCK_GET_TIME_FAILED,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&logger.mock, logger.base.create_entry, &logger, 0,
		MOCK_ARG_PTR_CONTAINS (&entry, sizeof (entry)), MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = debug_log_create_entry (1, 2, 3, 4, 5);
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, &rtc);
}

static void debug_log_test_flush (CuTest *test)
{
	struct logging_mock logger;
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = mock_expect (&logger.mock, logger.base.flush, &logger, 0);
	CuAssertIntEquals (test, 0, status);

	status = debug_log_flush ();
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_flush_no_log (CuTest *test)
{
	int status;

	TEST_START;

	debug_log = NULL;

	status = debug_log_flush ();
	CuAssertIntEquals (test, LOGGING_NO_LOG_AVAILABLE, status);
}

static void debug_log_test_clear (CuTest *test)
{
	struct logging_mock logger;
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = mock_expect (&logger.mock, logger.base.clear, &logger, 0);
	CuAssertIntEquals (test, 0, status);

	status = debug_log_clear ();
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_clear_no_log (CuTest *test)
{
	int status;

	TEST_START;

	debug_log = NULL;

	status = debug_log_clear ();
	CuAssertIntEquals (test, LOGGING_NO_LOG_AVAILABLE, status);
}

static void debug_log_test_get_size (CuTest *test)
{
	struct logging_mock logger;
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = mock_expect (&logger.mock, logger.base.get_size, &logger, 0);
	CuAssertIntEquals (test, 0, status);

	status = debug_log_get_size ();
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_get_size_no_log (CuTest *test)
{
	int status;

	TEST_START;

	debug_log = NULL;

	status = debug_log_get_size ();
	CuAssertIntEquals (test, LOGGING_NO_LOG_AVAILABLE, status);
}

static void debug_log_test_read_contents (CuTest *test)
{
	struct logging_mock logger;
	uint8_t contents[2];
	int status;

	TEST_START;

	setup_debug_log_mock_test (test, &logger, NULL);

	status = mock_expect (&logger.mock, logger.base.read_contents, &logger, 0, MOCK_ARG (0),
		MOCK_ARG_PTR (contents), MOCK_ARG (sizeof (contents)));
	CuAssertIntEquals (test, 0, status);

	status = debug_log_read_contents (0, contents, sizeof (contents));
	CuAssertIntEquals (test, 0, status);

	complete_debug_log_mock_test (test, &logger, NULL);
}

static void debug_log_test_read_contents_no_log (CuTest *test)
{
	uint8_t contents[2];
	int status;

	TEST_START;

	debug_log = NULL;

	status = debug_log_read_contents (0, contents, sizeof (contents));
	CuAssertIntEquals (test, LOGGING_NO_LOG_AVAILABLE, status);
}


TEST_SUITE_START (debug_log);

TEST (debug_log_test_create_entry);
TEST (debug_log_test_create_entry_no_log);
TEST (debug_log_test_create_entry_no_timestamp);
TEST (debug_log_test_create_entry_invalid_severity);
TEST (debug_log_test_create_entry_timestamp_error);
TEST (debug_log_test_flush);
TEST (debug_log_test_flush_no_log);
TEST (debug_log_test_clear);
TEST (debug_log_test_clear_no_log);
TEST (debug_log_test_get_size);
TEST (debug_log_test_get_size_no_log);
TEST (debug_log_test_read_contents);
TEST (debug_log_test_read_contents_no_log);

/* Tear down after the tests in this suite have run. */
TEST (debug_log_testing_suite_tear_down);

TEST_SUITE_END;
