// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/event_task.h"
#include "testing/mock/system/event_task_handler_mock.h"
#include "testing/mock/system/event_task_mock.h"


TEST_SUITE_LABEL ("event_task");


/**
 * Dependencies for testing.
 */
struct event_task_testing {
	struct event_task_handler_mock handler1;	/**< A mock event handler. */
	struct event_task_handler_mock handler2;	/**< A mock event handler. */
	struct event_task_handler_mock handler3;	/**< A mock event handler. */
	struct event_task_handler_mock handler4;	/**< A mock event handler. */
	struct event_task_mock task;				/**< A mock event task. */
	struct event_task_context context;			/**< Event context for event processing. */
	struct event_task_context *context_ptr;		/**< Pointer to the event context. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param event The testing components to initialize.
 */
static void event_task_testing_init_dependencies (CuTest *test, struct event_task_testing *event)
{
	int status;

	status = event_task_handler_mock_init (&event->handler1);
	CuAssertIntEquals (test, 0, status);

	status = event_task_handler_mock_init (&event->handler2);
	CuAssertIntEquals (test, 0, status);

	status = event_task_handler_mock_init (&event->handler3);
	CuAssertIntEquals (test, 0, status);

	status = event_task_handler_mock_init (&event->handler4);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&event->handler1.mock, "event_task_handler1");
	mock_set_name (&event->handler2.mock, "event_task_handler2");
	mock_set_name (&event->handler3.mock, "event_task_handler3");
	mock_set_name (&event->handler4.mock, "event_task_handler4");

	status = event_task_mock_init (&event->task);
	CuAssertIntEquals (test, 0, status);

	memset (&event->context, 0, sizeof (event->context));
	event->context_ptr = &event->context;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param event The testing components to release.
 */
static void event_task_testing_validate_and_release_dependencies (CuTest *test,
	struct event_task_testing *event)
{
	int status;

	status = event_task_handler_mock_validate_and_release (&event->handler1);
	status |= event_task_handler_mock_validate_and_release (&event->handler2);
	status |= event_task_handler_mock_validate_and_release (&event->handler3);
	status |= event_task_handler_mock_validate_and_release (&event->handler4);
	status |= event_task_mock_validate_and_release (&event->task);

	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void event_task_test_prepare_handlers (CuTest *test)
{
	struct event_task_testing event;
	int status;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.handler1.mock, event.handler1.base.prepare, &event.handler1, 0);
	CuAssertIntEquals (test, 0, status);

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_no_prepare (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	event.handler1.base.prepare = NULL;

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_multiple (CuTest *test)
{
	struct event_task_testing event;
	int status;
	const struct event_task_handler *list[] = {
		&event.handler1.base, &event.handler2.base, &event.handler3.base, &event.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.handler1.mock, event.handler1.base.prepare, &event.handler1, 0);
	status |= mock_expect (&event.handler2.mock, event.handler2.base.prepare, &event.handler2, 0);
	status |= mock_expect (&event.handler3.mock, event.handler3.base.prepare, &event.handler3, 0);
	status |= mock_expect (&event.handler4.mock, event.handler4.base.prepare, &event.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_multiple_with_no_prepare (CuTest *test)
{
	struct event_task_testing event;
	int status;
	const struct event_task_handler *list[] = {
		&event.handler1.base, &event.handler2.base, &event.handler3.base, &event.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	event.handler3.base.prepare = NULL;

	status = mock_expect (&event.handler1.mock, event.handler1.base.prepare, &event.handler1, 0);
	status |= mock_expect (&event.handler2.mock, event.handler2.base.prepare, &event.handler2, 0);
	status |= mock_expect (&event.handler4.mock, event.handler4.base.prepare, &event.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_null (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	event_task_prepare_handlers (NULL, count);
	event_task_prepare_handlers (list, 0);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_null_handler (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		NULL
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_prepare_handlers_multiple_with_null_handler (CuTest *test)
{
	struct event_task_testing event;
	int status;
	const struct event_task_handler *list[] = {
		&event.handler1.base, NULL, &event.handler3.base, &event.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.handler1.mock, event.handler1.base.prepare, &event.handler1, 0);
	status |= mock_expect (&event.handler3.mock, event.handler3.base.prepare, &event.handler3, 0);
	status |= mock_expect (&event.handler4.mock, event.handler4.base.prepare, &event.handler4, 0);

	CuAssertIntEquals (test, 0, status);

	event_task_prepare_handlers (list, count);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (&event.handler1.base, list, count);
	CuAssertIntEquals (test, 0, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler_not_found (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (&event.handler2.base, list, count);
	CuAssertIntEquals (test, EVENT_TASK_UNKNOWN_HANDLER, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler_multiple (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base, &event.handler2.base, &event.handler3.base, &event.handler4.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (&event.handler4.base, list, count);
	CuAssertIntEquals (test, 3, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler_multiple_not_found (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base, &event.handler2.base, &event.handler3.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (&event.handler4.base, list, count);
	CuAssertIntEquals (test, EVENT_TASK_UNKNOWN_HANDLER, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler_no_handlers (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = 0;
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (&event.handler1.base, list, count);
	CuAssertIntEquals (test, EVENT_TASK_UNKNOWN_HANDLER, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_find_handler_null (CuTest *test)
{
	struct event_task_testing event;
	const struct event_task_handler *list[] = {
		&event.handler1.base
	};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_find_handler (NULL, list, count);
	CuAssertIntEquals (test, EVENT_TASK_UNKNOWN_HANDLER, status);

	status = event_task_find_handler (&event.handler1.base, NULL, count);
	CuAssertIntEquals (test, EVENT_TASK_INVALID_ARGUMENT, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &event.context_ptr,
		sizeof (event.context_ptr), -1);

	status |= mock_expect (&event.task.mock, event.task.base.notify, &event.task, 0,
		MOCK_ARG (&event.handler1.base));

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1234, event_status);
	CuAssertIntEquals (test, action, event.context.action);
	CuAssertIntEquals (test, sizeof (data), event.context.buffer_length);

	status = testing_validate_array (data, event.context.event_buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_cast_value (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	size_t value = 0x112233;
	int event_status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &event.context_ptr,
		sizeof (event.context_ptr), -1);

	status |= mock_expect (&event.task.mock, event.task.base.notify, &event.task, 0,
		MOCK_ARG (&event.handler1.base));

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action,
		(uint8_t*) &value, sizeof (value), 4321, &event_status);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 4321, event_status);
	CuAssertIntEquals (test, action, event.context.action);
	CuAssertIntEquals (test, sizeof (value), event.context.buffer_length);
	CuAssertIntEquals (test, value, *((size_t*) event.context.event_buffer));

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_no_data (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 12;
	int event_status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &event.context_ptr,
		sizeof (event.context_ptr), -1);

	status |= mock_expect (&event.task.mock, event.task.base.notify, &event.task, 0,
		MOCK_ARG (&event.handler1.base));

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, NULL, 5, 1234,
		&event_status);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 1234, event_status);
	CuAssertIntEquals (test, action, event.context.action);
	CuAssertIntEquals (test, 0, event.context.buffer_length);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_no_status_out (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &event.context_ptr,
		sizeof (event.context_ptr), -1);

	status |= mock_expect (&event.task.mock, event.task.base.notify, &event.task, 0,
		MOCK_ARG (&event.handler1.base));

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, action, event.context.action);
	CuAssertIntEquals (test, sizeof (data), event.context.buffer_length);

	status = testing_validate_array (data, event.context.event_buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_null (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = event_task_submit_event (NULL, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_INVALID_ARGUMENT, status);

	status = event_task_submit_event (&event.task.base, NULL, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_INVALID_ARGUMENT, status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_no_task (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status = 1122;
	void *null_ptr = NULL;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_NO_TASK, status);
	CuAssertIntEquals (test, 1122, event_status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_task_busy (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status = 1122;
	void *null_ptr = NULL;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_BUSY, status);
	CuAssertIntEquals (test, 1122, event_status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_get_context_error (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status = 1122;
	void *null_ptr = NULL;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);
	CuAssertIntEquals (test, 1122, event_status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}

static void event_task_test_submit_event_notify_error (CuTest *test)
{
	struct event_task_testing event;
	int status;
	uint32_t action = 1;
	uint8_t data[] = {0x11, 0x22, 0x33, 0x44, 0x55};
	int event_status = 1122;

	TEST_START;

	event_task_testing_init_dependencies (test, &event);

	status = mock_expect (&event.task.mock, event.task.base.get_event_context, &event.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&event.task.mock, 0, &event.context_ptr,
		sizeof (event.context_ptr), -1);

	status |= mock_expect (&event.task.mock, event.task.base.notify, &event.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG (&event.handler1.base));

	CuAssertIntEquals (test, 0, status);

	status = event_task_submit_event (&event.task.base, &event.handler1.base, action, data,
		sizeof (data), 1234, &event_status);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);
	CuAssertIntEquals (test, 1234, event_status);

	event_task_testing_validate_and_release_dependencies (test, &event);
}


TEST_SUITE_START (event_task);

TEST (event_task_test_prepare_handlers);
TEST (event_task_test_prepare_handlers_no_prepare);
TEST (event_task_test_prepare_handlers_multiple);
TEST (event_task_test_prepare_handlers_multiple_with_no_prepare);
TEST (event_task_test_prepare_handlers_null);
TEST (event_task_test_prepare_handlers_null_handler);
TEST (event_task_test_prepare_handlers_multiple_with_null_handler);
TEST (event_task_test_find_handler);
TEST (event_task_test_find_handler_not_found);
TEST (event_task_test_find_handler_multiple);
TEST (event_task_test_find_handler_multiple_not_found);
TEST (event_task_test_find_handler_no_handlers);
TEST (event_task_test_find_handler_null);
TEST (event_task_test_submit_event);
TEST (event_task_test_submit_event_cast_value);
TEST (event_task_test_submit_event_no_data);
TEST (event_task_test_submit_event_no_status_out);
TEST (event_task_test_submit_event_null);
TEST (event_task_test_submit_event_no_task);
TEST (event_task_test_submit_event_task_busy);
TEST (event_task_test_submit_event_get_context_error);
TEST (event_task_test_submit_event_notify_error);

TEST_SUITE_END;
