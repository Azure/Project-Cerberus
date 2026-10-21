// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "system/fatal_error.h"
#include "system/system_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/fatal_error_handler_mock.h"


TEST_SUITE_LABEL ("fatal_error");


/**
 * Dependencies for testing.
 */
struct fatal_error_testing {
	struct fatal_error_handler_mock handler;	/**< Mock for fatal error handling. */
	struct logging_mock log;					/**< Mock for the debug log. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param error The testing components to initialize.
 */
static void fatal_error_testing_init_dependencies (CuTest *test, struct fatal_error_testing *error)
{
	int status;

	status = fatal_error_handler_mock_init (&error->handler);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&error->log);
	CuAssertIntEquals (test, 0, status);

	fatal_error = &error->handler.base;
	debug_log = &error->log.base;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param error The testing components to release.
 */
static void fatal_error_testing_validate_and_release_dependencies (CuTest *test,
	struct fatal_error_testing *error)
{
	int status;

	fatal_error = NULL;
	debug_log = NULL;

	status = fatal_error_handler_mock_validate_and_release (&error->handler);
	status |= logging_mock_validate_and_release (&error->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void fatal_error_testing_suite_tear_down (CuTest *test)
{
	fatal_error = NULL;
	debug_log = NULL;
}


/*******************
 * Test cases
 *******************/

static void fatal_error_test_unrecoverable_error (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x1234;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_FATAL_ERROR,
		.arg1 = error_code,
		.arg2 = 0
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	status = mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&error.log.mock, error.log.base.flush, &error.log, 0);

	status |= mock_expect (&error.handler.mock, error.handler.base.unrecoverable_error,
		&error.handler, 0);

	CuAssertIntEquals (test, 0, status);

	fatal_error_unrecoverable_error (error_code);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_unrecoverable_error_no_handler (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x87654321;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_FATAL_ERROR,
		.arg1 = error_code,
		.arg2 = 0
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	fatal_error = NULL;

	status = mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&error.log.mock, error.log.base.flush, &error.log, 0);

	CuAssertIntEquals (test, 0, status);

	fatal_error_unrecoverable_error (error_code);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x5678;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x12,
		.msg_index = 0x34,
		.arg1 = 0x5566,
		.arg2 = 0x7788
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	status = mock_expect (&error.handler.mock, error.handler.base.panic, &error.handler, 0,
		MOCK_ARG (error_code), MOCK_ARG_PTR_CONTAINS (&entry, sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic (error_code, &entry);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic_no_log_entry (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x12345678;
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	status = mock_expect (&error.handler.mock, error.handler.base.panic, &error.handler, 0,
		MOCK_ARG (error_code), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic (error_code, NULL);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic_no_handler (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x5678;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_FATAL_ERROR,
		.arg1 = error_code,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_extra = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x12,
		.msg_index = 0x34,
		.arg1 = 0x5566,
		.arg2 = 0x7788
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	fatal_error = NULL;

	status = mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_extra, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_extra)));

	status |= mock_expect (&error.log.mock, error.log.base.flush, &error.log, 0);

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic (error_code, &entry_extra);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic_no_handler_no_log_entry (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x5678;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_FATAL_ERROR,
		.arg1 = error_code,
		.arg2 = 0
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	fatal_error = NULL;

	status = mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&error.log.mock, error.log.base.flush, &error.log, 0);

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic (error_code, NULL);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic_create_entry (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x5678;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x12,
		.msg_index = 0x34,
		.arg1 = 0x5566,
		.arg2 = 0x7788
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	status = mock_expect (&error.handler.mock, error.handler.base.panic, &error.handler, 0,
		MOCK_ARG (error_code), MOCK_ARG_PTR_CONTAINS (&entry, sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic_create_entry (error_code, DEBUG_LOG_SEVERITY_ERROR, 0x12, 0x34, 0x5566,
		0x7788);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}

static void fatal_error_test_panic_create_entry_no_handler (CuTest *test)
{
	struct fatal_error_testing error;
	int error_code = 0x12345;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_FATAL_ERROR,
		.arg1 = error_code,
		.arg2 = 0
	};
	struct debug_log_entry_info entry_extra = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = 0x98,
		.msg_index = 0x76,
		.arg1 = 0x5544,
		.arg2 = 0x3322
	};
	int status;

	TEST_START;

	fatal_error_testing_init_dependencies (test, &error);

	fatal_error = NULL;

	status = mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&error.log.mock, error.log.base.create_entry, &error.log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry_extra, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry_extra)));

	status |= mock_expect (&error.log.mock, error.log.base.flush, &error.log, 0);

	CuAssertIntEquals (test, 0, status);

	fatal_error_panic_create_entry (error_code, DEBUG_LOG_SEVERITY_WARNING, 0x98, 0x76, 0x5544,
		0x3322);

	fatal_error_testing_validate_and_release_dependencies (test, &error);
}


// *INDENT-OFF*
TEST_SUITE_START (fatal_error);

TEST (fatal_error_test_unrecoverable_error);
TEST (fatal_error_test_unrecoverable_error_no_handler);
TEST (fatal_error_test_panic);
TEST (fatal_error_test_panic_no_log_entry);
TEST (fatal_error_test_panic_no_handler);
TEST (fatal_error_test_panic_no_handler_no_log_entry);
TEST (fatal_error_test_panic_create_entry);
TEST (fatal_error_test_panic_create_entry_no_handler);

/* Tear down after the tests in this suite have run. */
TEST (fatal_error_testing_suite_tear_down);

TEST_SUITE_END;
// *INDENT-ON*
