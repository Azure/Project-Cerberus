// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/periodic_task.h"
#include "testing/mock/system/periodic_task_handler_mock.h"


TEST_SUITE_LABEL ("periodic_task");


/**
 * Dependencies for testing.
 */
struct periodic_task_testing {
	struct periodic_task_handler_mock handler1;	/**< A mock periodic handler. */
	struct periodic_task_handler_mock handler2;	/**< A mock periodic handler. */
	struct periodic_task_handler_mock handler3;	/**< A mock periodic handler. */
	struct periodic_task_handler_mock handler4;	/**< A mock periodic handler. */
	platform_clock start;						/**< Start time of the test. */
	platform_clock time_500ms;					/**< A time 500ms in the future. */
	platform_clock time_1000ms;					/**< A time 1000ms in the future. */
	platform_clock time_1500ms;					/**< A time 1500ms in the future. */
	platform_clock time_2000ms;					/**< A time 2000ms in the future. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param periodic The testing components to initialize.
 */
static void periodic_task_testing_init_dependencies (CuTest *test,
	struct periodic_task_testing *periodic)
{
	int status;

	status = periodic_task_handler_mock_init (&periodic->handler1);
	CuAssertIntEquals (test, 0, status);

	status = periodic_task_handler_mock_init (&periodic->handler2);
	CuAssertIntEquals (test, 0, status);

	status = periodic_task_handler_mock_init (&periodic->handler3);
	CuAssertIntEquals (test, 0, status);

	status = periodic_task_handler_mock_init (&periodic->handler4);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&periodic->handler1.mock, "periodic_task_handler1");
	mock_set_name (&periodic->handler2.mock, "periodic_task_handler2");
	mock_set_name (&periodic->handler3.mock, "periodic_task_handler3");
	mock_set_name (&periodic->handler4.mock, "periodic_task_handler4");
}

/**
 * Initialize the timeouts for the test.
 *
 * @param test The testing framework.
 * @param periodic The testing components to initialize.
 */
static void periodic_task_testing_init_times (CuTest *test, struct periodic_task_testing *periodic)
{
	int status;

	status = platform_init_current_tick (&periodic->start);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (500, &periodic->time_500ms);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (1000, &periodic->time_1000ms);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (1500, &periodic->time_1500ms);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_timeout (2000, &periodic->time_2000ms);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param periodic The testing components to release.
 */
static void periodic_task_testing_validate_and_release_dependencies (CuTest *test,
	struct periodic_task_testing *periodic)
{
	int status;

	status = periodic_task_handler_mock_validate_and_release (&periodic->handler1);
	status |= periodic_task_handler_mock_validate_and_release (&periodic->handler2);
	status |= periodic_task_handler_mock_validate_and_release (&periodic->handler3);
	status |= periodic_task_handler_mock_validate_and_release (&periodic->handler4);

	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void periodic_task_test_prepare_handlers (CuTest *test)
{
	struct periodic_task_testing periodic;
	int status;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.prepare,
		&periodic.handler1, 0);
	CuAssertIntEquals (test, 0, status);

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_no_prepare (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	periodic.handler1.base.prepare = NULL;

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_multiple (CuTest *test)
{
	struct periodic_task_testing periodic;
	int status;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.prepare,
		&periodic.handler1, 0);
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.prepare,
		&periodic.handler2, 0);
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.prepare,
		&periodic.handler3, 0);
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.prepare,
		&periodic.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_multiple_with_no_prepare (CuTest *test)
{
	struct periodic_task_testing periodic;
	int status;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	periodic.handler3.base.prepare = NULL;

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.prepare,
		&periodic.handler1, 0);
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.prepare,
		&periodic.handler2, 0);
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.prepare,
		&periodic.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_null (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	periodic_task_prepare_handlers (NULL, count);
	periodic_task_prepare_handlers (list, 0);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_null_handler (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		NULL
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_prepare_handlers_multiple_with_null_handler (CuTest *test)
{
	struct periodic_task_testing periodic;
	int status;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, NULL, &periodic.handler3.base, &periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.prepare,
		&periodic.handler1, 0);
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.prepare,
		&periodic.handler3, 0);
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.prepare,
		&periodic.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_prepare_handlers (list, count);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_500ms));

	status |= mock_expect (&periodic.handler1.mock, periodic.handler1.base.execute,
		&periodic.handler1.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) >= 500));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_null_execution_time (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&periodic.handler1.mock, periodic.handler1.base.execute,
		&periodic.handler1.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 50));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_multiple (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_1000ms));
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.get_next_execution,
		&periodic.handler2.base, MOCK_RETURN_PTR (&periodic.time_1500ms));
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.get_next_execution,
		&periodic.handler3.base, MOCK_RETURN_PTR (&periodic.time_500ms));
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.get_next_execution,
		&periodic.handler4.base, MOCK_RETURN_PTR (&periodic.time_2000ms));

	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.execute,
		&periodic.handler3.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) >= 500));
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 1000));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_multiple_same_timeout (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_1500ms));
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.get_next_execution,
		&periodic.handler2.base, MOCK_RETURN_PTR (&periodic.time_500ms));
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.get_next_execution,
		&periodic.handler3.base, MOCK_RETURN_PTR (&periodic.time_2000ms));
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.get_next_execution,
		&periodic.handler4.base, MOCK_RETURN_PTR (&periodic.time_500ms));

	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.execute,
		&periodic.handler2.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) >= 500));
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 1500));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_multiple_null_execution_time (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_1000ms));
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.get_next_execution,
		&periodic.handler2.base, MOCK_RETURN_PTR (&periodic.time_500ms));
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.get_next_execution,
		&periodic.handler3.base, MOCK_RETURN_PTR (NULL));
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.get_next_execution,
		&periodic.handler4.base, MOCK_RETURN_PTR (NULL));

	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.execute,
		&periodic.handler3.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 50));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_expired_timeout (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, &periodic.handler3.base,
		&periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_1000ms));
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.get_next_execution,
		&periodic.handler2.base, MOCK_RETURN_PTR (&periodic.time_1500ms));
	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.get_next_execution,
		&periodic.handler3.base, MOCK_RETURN_PTR (&periodic.time_500ms));
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.get_next_execution,
		&periodic.handler4.base, MOCK_RETURN_PTR (&periodic.time_2000ms));

	status |= mock_expect (&periodic.handler3.mock, periodic.handler3.base.execute,
		&periodic.handler3.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);
	platform_msleep (510);

	status = platform_init_current_tick (&periodic.start);
	CuAssertIntEquals (test, 0, status);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 50));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_null (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = periodic_task_execute_next_handler (NULL, count);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	status = periodic_task_execute_next_handler (list, 0);
	CuAssertIntEquals (test, PERIODIC_TASK_INVALID_ARGUMENT, status);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_null_handler (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		NULL
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, PERIODIC_TASK_NO_HANDLERS, status);

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}

static void periodic_task_test_execute_next_handler_multiple_with_null_handler (CuTest *test)
{
	struct periodic_task_testing periodic;
	const struct periodic_task_handler *list[] = {
		&periodic.handler1.base, &periodic.handler2.base, NULL, &periodic.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;
	platform_clock end;

	TEST_START;

	periodic_task_testing_init_dependencies (test, &periodic);

	status = mock_expect (&periodic.handler1.mock, periodic.handler1.base.get_next_execution,
		&periodic.handler1.base, MOCK_RETURN_PTR (&periodic.time_500ms));
	status |= mock_expect (&periodic.handler2.mock, periodic.handler2.base.get_next_execution,
		&periodic.handler2.base, MOCK_RETURN_PTR (&periodic.time_1500ms));
	status |= mock_expect (&periodic.handler4.mock, periodic.handler4.base.get_next_execution,
		&periodic.handler4.base, MOCK_RETURN_PTR (&periodic.time_2000ms));

	status |= mock_expect (&periodic.handler1.mock, periodic.handler1.base.execute,
		&periodic.handler1.base, 0);

	CuAssertIntEquals (test, 0, status);

	periodic_task_testing_init_times (test, &periodic);

	status = periodic_task_execute_next_handler (list, count);
	CuAssertIntEquals (test, 0, status);

	status = platform_init_current_tick (&end);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) >= 500));
	CuAssertTrue (test, (platform_get_duration (&periodic.start, &end) < 1500));

	periodic_task_testing_validate_and_release_dependencies (test, &periodic);
}


// *INDENT-OFF*
TEST_SUITE_START (periodic_task);

TEST (periodic_task_test_prepare_handlers);
TEST (periodic_task_test_prepare_handlers_no_prepare);
TEST (periodic_task_test_prepare_handlers_multiple);
TEST (periodic_task_test_prepare_handlers_multiple_with_no_prepare);
TEST (periodic_task_test_prepare_handlers_null);
TEST (periodic_task_test_prepare_handlers_null_handler);
TEST (periodic_task_test_prepare_handlers_multiple_with_null_handler);
TEST (periodic_task_test_execute_next_handler);
TEST (periodic_task_test_execute_next_handler_null_execution_time);
TEST (periodic_task_test_execute_next_handler_multiple);
TEST (periodic_task_test_execute_next_handler_multiple_same_timeout);
TEST (periodic_task_test_execute_next_handler_multiple_null_execution_time);
TEST (periodic_task_test_execute_next_handler_expired_timeout);
TEST (periodic_task_test_execute_next_handler_null);
TEST (periodic_task_test_execute_next_handler_null_handler);
TEST (periodic_task_test_execute_next_handler_multiple_with_null_handler);

TEST_SUITE_END;
// *INDENT-ON*
