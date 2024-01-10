// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "logging/log_flush_handler.h"
#include "logging/log_flush_handler_static.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("log_flush_handler");


/**
 * Maximum expected length of time consumed until the next handler can execute.
 */
#define LOG_FLUSH_HANDLER_TESTING_NEXT_THRESHOLD_MS		100


/**
 * Dependencies for testing.
 */
struct log_flush_handler_testing {
	struct logging_mock log1;				/**< Log for testing. */
	struct logging_mock log2;				/**< Log for testing. */
	struct logging_mock log3;				/**< Log for testing. */
	struct log_flush_handler_state state;	/**< Context for the test being tested. */
	struct log_flush_handler test;			/**< Log flush task for testing. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void log_flush_handler_testing_init_dependencies (CuTest *test,
	struct log_flush_handler_testing *handler)
{
	int status;

	status = logging_mock_init (&handler->log1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->log1.mock, "log1");

	status = logging_mock_init (&handler->log2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->log2.mock, "log2");

	status = logging_mock_init (&handler->log3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->log3.mock, "log3");
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param log_list List of logs to use with the handler.
 * @param log_count Number of logs in the list.
 * @param period_ms Time between handler executions.
 */
static void log_flush_handler_testing_init (CuTest *test, struct log_flush_handler_testing *handler,
	const struct logging **log_list, size_t log_count, uint32_t period_ms)
{
	int status;

	log_flush_handler_testing_init_dependencies (test, handler);

	status = log_flush_handler_init (&handler->test, &handler->state, log_list, log_count,
		period_ms);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static, instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param test_static The static handler to initialize.
 */
static void log_flush_handler_testing_init_static (CuTest *test,
	struct log_flush_handler_testing *handler, struct log_flush_handler *test_static)
{
	int status;

	log_flush_handler_testing_init_dependencies (test, handler);

	status = log_flush_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void log_flush_handler_testing_release_dependencies (CuTest *test,
	struct log_flush_handler_testing *handler)
{
	int status;

	status = logging_mock_validate_and_release (&handler->log1);
	status |= logging_mock_validate_and_release (&handler->log2);
	status |= logging_mock_validate_and_release (&handler->log3);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void log_flush_handler_testing_validate_and_release (CuTest *test,
	struct log_flush_handler_testing *handler)
{
	log_flush_handler_testing_release_dependencies (test, handler);
	log_flush_handler_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void log_flush_handler_test_init (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	int status;

	TEST_START;

	log_flush_handler_testing_init_dependencies (test, &handler);

	status = log_flush_handler_init (&handler.test, &handler.state, log_list, log_count, 100);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	log_flush_handler_testing_validate_and_release (test, &handler);
}

static void log_flush_handler_test_init_null (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	int status;

	TEST_START;

	log_flush_handler_testing_init_dependencies (test, &handler);

	status = log_flush_handler_init (NULL, &handler.state, log_list, log_count, 100);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = log_flush_handler_init (&handler.test, NULL, log_list, log_count, 100);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = log_flush_handler_init (&handler.test, &handler.state, NULL, log_count, 100);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	status = log_flush_handler_init (&handler.test, &handler.state, log_list, 0, 100);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	log_flush_handler_testing_release_dependencies(test, &handler);
}

static void log_flush_handler_test_static_init (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	struct log_flush_handler test_static = log_flush_handler_static_init (&handler.state, log_list,
		log_count, 500);
	int status;

	TEST_START;

	log_flush_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.base.prepare);
	CuAssertPtrNotNull (test, test_static.base.get_next_execution);
	CuAssertPtrNotNull (test, test_static.base.execute);

	status = log_flush_handler_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	log_flush_handler_testing_release_dependencies (test, &handler);
	log_flush_handler_release (&test_static);
}

static void log_flush_handler_test_static_init_null (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	struct log_flush_handler test_static = log_flush_handler_static_init (&handler.state, log_list,
		log_count, 500);
	int status;

	TEST_START;

	log_flush_handler_testing_init_dependencies (test, &handler);

	status = log_flush_handler_init_state (NULL);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = log_flush_handler_init_state (&test_static);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	test_static.state = &handler.state;
	test_static.logs = NULL;
	status = log_flush_handler_init_state (&test_static);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	test_static.logs = log_list;
	test_static.log_count = 0;
	status = log_flush_handler_init_state (&test_static);
	CuAssertIntEquals (test, LOGGING_INVALID_ARGUMENT, status);

	log_flush_handler_testing_release_dependencies (test, &handler);
}

static void log_flush_handler_test_release_null (CuTest *test)
{
	TEST_START;

	log_flush_handler_release (NULL);
}

static void log_flush_handler_test_get_next_execution (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	log_flush_handler_testing_init (test, &handler, log_list, log_count, 1000);

	handler.test.base.prepare (&handler.test.base);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > (1000 - LOG_FLUSH_HANDLER_TESTING_NEXT_THRESHOLD_MS)));	/* Apply reasonable bounds for testing. */

	log_flush_handler_testing_validate_and_release (test, &handler);
}

static void log_flush_handler_test_get_next_execution_no_prepare (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	const platform_clock *next_time;

	TEST_START;

	log_flush_handler_testing_init (test, &handler, log_list, log_count, 1000);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	log_flush_handler_testing_validate_and_release (test, &handler);
}

static void log_flush_handler_test_get_next_execution_static_init (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	struct log_flush_handler test_static = log_flush_handler_static_init (&handler.state, log_list,
		log_count, 5000);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	log_flush_handler_testing_init_static (test, &handler, &test_static);

	test_static.base.prepare (&test_static.base);

	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 5000));
	CuAssertTrue (test, (msec > 4950));	/* Apply reasonable bounds for testing. */

	log_flush_handler_testing_release_dependencies (test, &handler);
	log_flush_handler_release (&test_static);
}

static void log_flush_handler_test_execute (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	log_flush_handler_testing_init (test, &handler, log_list, log_count, 1000);

	status = mock_expect (&handler.log1.mock, handler.log1.base.flush, &handler.log1, 0);
	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > (1000 - LOG_FLUSH_HANDLER_TESTING_NEXT_THRESHOLD_MS)));	/* Apply reasonable bounds for testing. */

	log_flush_handler_testing_validate_and_release (test, &handler);
}

static void log_flush_handler_test_execute_multiple_logs (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base, &handler.log2.base, &handler.log3.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	log_flush_handler_testing_init (test, &handler, log_list, log_count, 1000);

	status = mock_expect (&handler.log1.mock, handler.log1.base.flush, &handler.log1, 0);
	status |= mock_expect (&handler.log2.mock, handler.log2.base.flush, &handler.log2, 0);
	status |= mock_expect (&handler.log3.mock, handler.log3.base.flush, &handler.log3, 0);

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > (1000 - LOG_FLUSH_HANDLER_TESTING_NEXT_THRESHOLD_MS)));	/* Apply reasonable bounds for testing. */

	log_flush_handler_testing_validate_and_release (test, &handler);
}

static void log_flush_handler_test_execute_static_init (CuTest *test)
{
	struct log_flush_handler_testing handler;
	const struct logging *log_list[] = {&handler.log1.base};
	const size_t log_count = sizeof (log_list) / sizeof (log_list[0]);
	struct log_flush_handler test_static = log_flush_handler_static_init (&handler.state, log_list,
		log_count, 5000);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	log_flush_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.log1.mock, handler.log1.base.flush, &handler.log1, 0);
	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	test_static.base.prepare (&test_static.base);
	platform_msleep (200);

	test_static.base.execute (&test_static.base);

	/* Check the the timeout has been updated. */
	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 5000));
	CuAssertTrue (test, (msec > 4950));	/* Apply reasonable bounds for testing. */

	log_flush_handler_testing_release_dependencies (test, &handler);
	log_flush_handler_release (&test_static);
}


TEST_SUITE_START (log_flush_handler);

TEST (log_flush_handler_test_init);
TEST (log_flush_handler_test_init_null);
TEST (log_flush_handler_test_static_init);
TEST (log_flush_handler_test_static_init_null);
TEST (log_flush_handler_test_release_null);
TEST (log_flush_handler_test_get_next_execution);
TEST (log_flush_handler_test_get_next_execution_no_prepare);
TEST (log_flush_handler_test_get_next_execution_static_init);
TEST (log_flush_handler_test_execute);
TEST (log_flush_handler_test_execute_multiple_logs);
TEST (log_flush_handler_test_execute_static_init);

TEST_SUITE_END;
