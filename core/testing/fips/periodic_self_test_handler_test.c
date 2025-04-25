// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "common/unused.h"
#include "crypto/aes_cbc.h"
#include "fips/fips_logging.h"
#include "fips/periodic_self_test_handler.h"
#include "fips/periodic_self_test_handler_static.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/fips/error_state_entry_mock.h"
#include "testing/mock/fips/self_test_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("periodic_self_test_handler");


/**
 * Dependencies for testing the periodic self-test handler.
 */
struct periodic_self_test_handler_testing {
	struct self_test_mock self_test[3];				/**< Mock for self-tests. */
	const struct self_test_interface *list[3];		/**< List of self-tests. */
	struct error_state_entry_mock error_state;		/**< Mock for error state handling. */
	struct logging_mock log;						/**< Mock for the debug log. */
	struct periodic_self_test_handler_state state;	/**< Variable state for the handler. */
	struct periodic_self_test_handler test;			/**< Handler instance under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param handler Testing dependencies to initialize.
 */
static void periodic_self_test_handler_testing_init_dependencies (CuTest *test,
	struct periodic_self_test_handler_testing *handler)
{
	int status;

	status = self_test_mock_init (&handler->self_test[0]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&handler->self_test[0].mock, "self_test[0]");
	handler->list[0] = &handler->self_test[0].base;

	status = self_test_mock_init (&handler->self_test[1]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&handler->self_test[1].mock, "self_test[1]");
	handler->list[1] = &handler->self_test[1].base;

	status = self_test_mock_init (&handler->self_test[2]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&handler->self_test[2].mock, "self_test[2]");
	handler->list[2] = &handler->self_test[2].base;

	status = error_state_entry_mock_init (&handler->error_state);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &handler->log.base;
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param handler Testing dependencies to release.
 */
static void periodic_self_test_handler_testing_release_dependencies (CuTest *test,
	struct periodic_self_test_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = self_test_mock_validate_and_release (&handler->self_test[0]);
	status |= self_test_mock_validate_and_release (&handler->self_test[1]);
	status |= self_test_mock_validate_and_release (&handler->self_test[2]);
	status |= error_state_entry_mock_validate_and_release (&handler->error_state);
	status |= logging_mock_validate_and_release (&handler->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a periodic self-test handler for testing.
 *
 * @param test The test framework.
 * @param handler Testing components to initialize.
 * @param test_count The number of tests to include in the handler.
 * @param interval Test interval to use.
 */
static void periodic_self_test_handler_testing_init (CuTest *test,
	struct periodic_self_test_handler_testing *handler, size_t test_count, uint32_t interval)
{
	int status;

	periodic_self_test_handler_testing_init_dependencies (test, handler);

	status = periodic_self_test_handler_init (&handler->test, &handler->state, handler->list,
		test_count, interval, &handler->error_state.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param handler Testing components to release.
 */
static void periodic_self_test_handler_testing_release (CuTest *test,
	struct periodic_self_test_handler_testing *handler)
{
	periodic_self_test_handler_release (&handler->test);
	periodic_self_test_handler_testing_release_dependencies (test, handler);
}


/*******************
 * Test cases
 *******************/

static void periodic_self_test_handler_test_init (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;

	TEST_START;

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	status = periodic_self_test_handler_init (&handler.test, &handler.state, handler.list,
		ARRAY_SIZE (handler.list), 1000, &handler.error_state.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_init_null (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;

	TEST_START;

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	status = periodic_self_test_handler_init (NULL, &handler.state, handler.list,
		ARRAY_SIZE (handler.list), 1000, &handler.error_state.base);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	status = periodic_self_test_handler_init (&handler.test, NULL, handler.list,
		ARRAY_SIZE (handler.list), 1000, &handler.error_state.base);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	status = periodic_self_test_handler_init (&handler.test, &handler.state, NULL,
		ARRAY_SIZE (handler.list), 1000, &handler.error_state.base);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	status = periodic_self_test_handler_init (&handler.test, &handler.state, handler.list, 0, 1000,
		&handler.error_state.base);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	status = periodic_self_test_handler_init (&handler.test, &handler.state, handler.list,
		ARRAY_SIZE (handler.list), 1000, NULL);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	periodic_self_test_handler_testing_release_dependencies (test, &handler);
}

static void periodic_self_test_handler_test_static_init (CuTest *test)
{
	struct periodic_self_test_handler_testing handler = {
		.test = periodic_self_test_handler_static_init (&handler.state, handler.list,
			ARRAY_SIZE (handler.list), 1000, &handler.error_state.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_release_null (CuTest *test)
{
	TEST_START;

	periodic_self_test_handler_release (NULL);
}

static void periodic_self_test_handler_test_prepare (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, ARRAY_SIZE (handler.list), 1000);

	handler.test.base.prepare (&handler.test.base);

	/* Check first execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_prepare_static_init (CuTest *test)
{
	struct periodic_self_test_handler_testing handler = {
		.test = periodic_self_test_handler_static_init (&handler.state, handler.list,
			ARRAY_SIZE (handler.list), 3000, &handler.error_state.base)
	};
	int status;
	const platform_clock *next;
	uint32_t remaining;

	TEST_START;

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	handler.test.base.prepare (&handler.test.base);

	/* Check first execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 3000) && (remaining >= 2998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_single_test (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, 1, 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_multiple_tests (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, ARRAY_SIZE (handler.list), 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.self_test[1].mock, handler.self_test[1].base.run_self_test,
		&handler.self_test[1], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.self_test[2].mock, handler.self_test[2].base.run_self_test,
		&handler.self_test[2], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_test_success_with_log_entry (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};
	struct debug_log_entry_info log = {
		.format = DEBUG_LOG_ENTRY_FORMAT + 1,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = 0x11,
		.msg_index = 0x22,
		.arg1 = 0x1234,
		.arg2 = 0x5678
	};
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = 0x11,
		.msg_index = 0x22,
		.arg1 = 0x1234,
		.arg2 = 0x5678
	};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, 1, 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[0].mock, 0, &log, sizeof (log), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_multiple_test_success_with_log_entries (
	CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};
	struct debug_log_entry_info log[3] = {
		{
			.format = DEBUG_LOG_ENTRY_FORMAT + 1,
			.severity = DEBUG_LOG_SEVERITY_INFO,
			.component = 0x11,
			.msg_index = 0x22,
			.arg1 = 0x1234,
			.arg2 = 0x5678
		},
		{
			.format = DEBUG_LOG_ENTRY_FORMAT + 1,
			.severity = DEBUG_LOG_SEVERITY_WARNING,
			.component = 0x33,
			.msg_index = 0x44,
			.arg1 = 0x9abc,
			.arg2 = 0xdef0
		},
		{
			.format = DEBUG_LOG_ENTRY_FORMAT + 1,
			.severity = DEBUG_LOG_SEVERITY_ERROR,
			.component = 0x55,
			.msg_index = 0x6,
			.arg1 = 0x12345678,
			.arg2 = 0x9abcdef0
		}
	};
	struct debug_log_entry_info entry[3] = {
		{
			.format = DEBUG_LOG_ENTRY_FORMAT,
			.severity = DEBUG_LOG_SEVERITY_INFO,
			.component = 0x11,
			.msg_index = 0x22,
			.arg1 = 0x1234,
			.arg2 = 0x5678
		},
		{
			.format = DEBUG_LOG_ENTRY_FORMAT,
			.severity = DEBUG_LOG_SEVERITY_WARNING,
			.component = 0x33,
			.msg_index = 0x44,
			.arg1 = 0x9abc,
			.arg2 = 0xdef0
		},
		{
			.format = DEBUG_LOG_ENTRY_FORMAT,
			.severity = DEBUG_LOG_SEVERITY_ERROR,
			.component = 0x55,
			.msg_index = 0x6,
			.arg1 = 0x12345678,
			.arg2 = 0x9abcdef0
		}
	};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, ARRAY_SIZE (handler.list), 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[0].mock, 0, &log[0], sizeof (log[0]), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry[0], LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry[0])));

	status |= mock_expect (&handler.self_test[1].mock, handler.self_test[1].base.run_self_test,
		&handler.self_test[1], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[1].mock, 0, &log[1], sizeof (log[1]), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry[1], LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry[1])));

	status |= mock_expect (&handler.self_test[2].mock, handler.self_test[2].base.run_self_test,
		&handler.self_test[2], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[2].mock, 0, &log[2], sizeof (log[2]), -1);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry[2], LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry[2])));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_static_init (CuTest *test)
{
	struct periodic_self_test_handler_testing handler = {
		.test = periodic_self_test_handler_static_init (&handler.state, handler.list,
			ARRAY_SIZE (handler.list), 3000, &handler.error_state.base)
	};
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};

	TEST_START;

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.self_test[1].mock, handler.self_test[1].base.run_self_test,
		&handler.self_test[1], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.self_test[2].mock, handler.self_test[2].base.run_self_test,
		&handler.self_test[2], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 3000) && (remaining >= 2998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_single_test_failure (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};
	struct debug_log_entry_info log = {
		.format = DEBUG_LOG_ENTRY_FORMAT + 1,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x11,
		.msg_index = 0x22,
		.arg1 = 0x1234,
		.arg2 = 0x5678
	};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, 1, 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], AES_CBC_ENGINE_SELF_TEST_FAILED,
		MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[0].mock, 0, &log, sizeof (log), -1);

	status |= mock_expect (&handler.error_state.mock, handler.error_state.base.enter_error_state,
		&handler.error_state, 0, MOCK_ARG_PTR_CONTAINS (&log, sizeof (log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_multiple_tests_failure (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};
	struct debug_log_entry_info log = {
		.format = DEBUG_LOG_ENTRY_FORMAT + 1,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x33,
		.msg_index = 0x44,
		.arg1 = 0x9abc,
		.arg2 = 0xdef0
	};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, ARRAY_SIZE (handler.list), 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], 0, MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.self_test[1].mock, handler.self_test[1].base.run_self_test,
		&handler.self_test[1], AES_CBC_ENGINE_SELF_TEST_FAILED,
		MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[1].mock, 0, &log, sizeof (log), -1);

	status |= mock_expect (&handler.error_state.mock, handler.error_state.base.enter_error_state,
		&handler.error_state, 0, MOCK_ARG_PTR_CONTAINS (&log, sizeof (log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_test_failure_no_log (CuTest *test)
{
	struct periodic_self_test_handler_testing handler;
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};

	TEST_START;

	periodic_self_test_handler_testing_init (test, &handler, 1, 1000);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], AES_CBC_ENGINE_SELF_TEST_FAILED,
		MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));

	status |= mock_expect (&handler.error_state.mock, handler.error_state.base.enter_error_state,
		&handler.error_state, 0, MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 1000) && (remaining >= 998)));

	periodic_self_test_handler_testing_release (test, &handler);
}

static void periodic_self_test_handler_test_execute_test_failure_static_init (CuTest *test)
{
	struct periodic_self_test_handler_testing handler = {
		.test = periodic_self_test_handler_static_init (&handler.state, handler.list,
			ARRAY_SIZE (handler.list), 3000, &handler.error_state.base)
	};
	int status;
	const platform_clock *next;
	uint32_t remaining;
	struct debug_log_entry_info empty_log = {0};
	struct debug_log_entry_info log = {
		.format = DEBUG_LOG_ENTRY_FORMAT + 1,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = 0x11,
		.msg_index = 0x22,
		.arg1 = 0x1234,
		.arg2 = 0x5678
	};

	TEST_START;

	periodic_self_test_handler_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.self_test[0].mock, handler.self_test[0].base.run_self_test,
		&handler.self_test[0], AES_CBC_ENGINE_SELF_TEST_FAILED,
		MOCK_ARG_PTR_CONTAINS (&empty_log, sizeof (empty_log)));
	status |= mock_expect_output (&handler.self_test[0].mock, 0, &log, sizeof (log), -1);

	status |= mock_expect (&handler.error_state.mock, handler.error_state.base.enter_error_state,
		&handler.error_state, 0, MOCK_ARG_PTR_CONTAINS (&log, sizeof (log)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	/* Check next execution time. */
	next = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, next);

	status = platform_get_timeout_remaining (next, &remaining);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, ((remaining <= 3000) && (remaining >= 2998)));

	periodic_self_test_handler_testing_release (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (periodic_self_test_handler);

TEST (periodic_self_test_handler_test_init);
TEST (periodic_self_test_handler_test_init_null);
TEST (periodic_self_test_handler_test_static_init);
TEST (periodic_self_test_handler_test_release_null);
TEST (periodic_self_test_handler_test_prepare);
TEST (periodic_self_test_handler_test_prepare_static_init);
TEST (periodic_self_test_handler_test_execute_single_test);
TEST (periodic_self_test_handler_test_execute_multiple_tests);
TEST (periodic_self_test_handler_test_execute_test_success_with_log_entry);
TEST (periodic_self_test_handler_test_execute_multiple_test_success_with_log_entries);
TEST (periodic_self_test_handler_test_execute_static_init);
TEST (periodic_self_test_handler_test_execute_single_test_failure);
TEST (periodic_self_test_handler_test_execute_multiple_tests_failure);
TEST (periodic_self_test_handler_test_execute_test_failure_no_log);
TEST (periodic_self_test_handler_test_execute_test_failure_static_init);

TEST_SUITE_END;
// *INDENT-ON*
