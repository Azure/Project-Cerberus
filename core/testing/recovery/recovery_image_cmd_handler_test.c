// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "recovery/recovery_image_cmd_handler.h"
#include "recovery/recovery_image_cmd_handler_static.h"
#include "recovery/recovery_logging.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/recovery/recovery_image_manager_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("recovery_image_cmd_handler");


/**
 * Dependencies for testing.
 */
struct recovery_image_cmd_handler_testing {
	struct recovery_image_manager_mock recovery;	/**< Mock for the manifest manager. */
	struct logging_mock log;						/**< Mock for debug logging. */
	struct event_task_mock task;					/**< Mock for the command task. */
	struct event_task_context context;				/**< Event context for event processing. */
	struct event_task_context *context_ptr;			/**< Pointer to the event context. */
	struct recovery_image_cmd_handler_state state;	/**< Context for the manifest handler. */
	struct recovery_image_cmd_handler test;			/**< Manifest handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void recovery_image_cmd_handler_testing_init_dependencies (CuTest *test,
	struct recovery_image_cmd_handler_testing *handler)
{
	int status;

	status = recovery_image_manager_mock_init (&handler->recovery);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	memset (&handler->context, 0, sizeof (handler->context));
	handler->context_ptr = &handler->context;

	debug_log = &handler->log.base;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void recovery_image_cmd_handler_testing_init (CuTest *test,
	struct recovery_image_cmd_handler_testing *handler)
{
	int status;

	recovery_image_cmd_handler_testing_init_dependencies (test, handler);

	status = recovery_image_cmd_handler_init (&handler->test, &handler->state,
		&handler->recovery.base, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void recovery_image_cmd_handler_testing_init_static (CuTest *test,
	struct recovery_image_cmd_handler_testing *handler,
	struct recovery_image_cmd_handler *test_static)
{
	int status;

	recovery_image_cmd_handler_testing_init_dependencies (test, handler);

	status = recovery_image_cmd_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void recovery_image_cmd_handler_testing_release_dependencies (CuTest *test,
	struct recovery_image_cmd_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = recovery_image_manager_mock_validate_and_release (&handler->recovery);
	status |= logging_mock_validate_and_release (&handler->log);
	status |= event_task_mock_validate_and_release (&handler->task);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void recovery_image_cmd_handler_testing_validate_and_release (CuTest *test,
	struct recovery_image_cmd_handler_testing *handler)
{
	recovery_image_cmd_handler_testing_release_dependencies (test, handler);
	recovery_image_cmd_handler_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void recovery_image_cmd_handler_test_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_dependencies (test, &handler);

	status = recovery_image_cmd_handler_init (&handler.test, &handler.state, &handler.recovery.base,
		&handler.task.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base_cmd.prepare_recovery_image);
	CuAssertPtrNotNull (test, handler.test.base_cmd.update_recovery_image);
	CuAssertPtrNotNull (test, handler.test.base_cmd.activate_recovery_image);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_init_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_dependencies (test, &handler);

	status = recovery_image_cmd_handler_init (NULL, &handler.state, &handler.recovery.base,
		&handler.task.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_cmd_handler_init (&handler.test, NULL, &handler.recovery.base,
		&handler.task.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_cmd_handler_init (&handler.test, &handler.state, NULL,
		&handler.task.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = recovery_image_cmd_handler_init (&handler.test, &handler.state, &handler.recovery.base,
		NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
}

static void recovery_image_cmd_handler_test_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.base_cmd.prepare_recovery_image);
	CuAssertPtrNotNull (test, test_static.base_cmd.update_recovery_image);
	CuAssertPtrNotNull (test, test_static.base_cmd.activate_recovery_image);
	CuAssertPtrNotNull (test, test_static.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, test_static.base_event.prepare);
	CuAssertPtrNotNull (test, test_static.base_event.execute);

	status = recovery_image_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_static_init_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_dependencies (test, &handler);

	status = recovery_image_cmd_handler_init_state (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = recovery_image_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = &handler.state;
	test_static.manager = NULL;
	status = recovery_image_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	test_static.manager = &handler.recovery.base;
	test_static.task = NULL;
	status = recovery_image_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_cmd_handler_release (NULL);
}

static void recovery_image_cmd_handler_test_get_status (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_get_status_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_get_status_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_status (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_UNKNOWN, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_recovery_image (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	uint32_t bytes = 5000;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.prepare_recovery_image (&test_static.base_cmd, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.prepare_recovery_image (NULL, bytes);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_no_task (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_recovery_image (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_task_busy (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_recovery_image (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_get_context_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_recovery_image (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_prepare_recovery_image_notify_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_recovery_image (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE, handler.context.action);
	CuAssertIntEquals (test, sizeof (image_data), handler.context.buffer_length);

	status = testing_validate_array (image_data, handler.context.event_buffer, sizeof (image_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_max_payload (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (image_data); i++) {
		image_data[i] = i;
	}

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE, handler.context.action);
	CuAssertIntEquals (test, sizeof (image_data), handler.context.buffer_length);

	status = testing_validate_array (image_data, handler.context.event_buffer, sizeof (image_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.update_recovery_image (&test_static.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE, handler.context.action);
	CuAssertIntEquals (test, sizeof (image_data), handler.context.buffer_length);

	status = testing_validate_array (image_data, handler.context.event_buffer, sizeof (image_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_update_recovery_image_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.update_recovery_image (NULL, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, NULL,
		sizeof (image_data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_too_much_data (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[EVENT_TASK_CONTEXT_BUFFER_LENGTH + 1];

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_TOO_MUCH_DATA, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_no_task (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_task_busy (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_get_context_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_update_recovery_image_notify_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.update_recovery_image (&handler.test.base_cmd, image_data,
		sizeof (image_data));
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.activate_recovery_image (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.activate_recovery_image (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_STARTING, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_null (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.activate_recovery_image (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_no_task (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.activate_recovery_image (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_task_busy (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.activate_recovery_image (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_get_context_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.activate_recovery_image (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_activate_recovery_image_notify_error (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.activate_recovery_image (&handler.test.base_cmd);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_prepare_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 100;
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock,
		handler.recovery.base.clear_recovery_image_region, &handler.recovery.base, 0,
		MOCK_ARG (bytes));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_prepare_recovery_image_failure (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 100;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_ERASE_FAIL,
		.arg1 = 2,
		.arg2 = RECOVERY_IMAGE_MANAGER_CLEAR_FAILED
	};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	recovery_image_manager_set_port (&handler.recovery.base, 2);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock,
		handler.recovery.base.clear_recovery_image_region, &handler.recovery.base,
		RECOVERY_IMAGE_MANAGER_CLEAR_FAILED, MOCK_ARG (bytes));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((RECOVERY_IMAGE_MANAGER_CLEAR_FAILED & 0x00ffffff) << 8) |
			RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL),
		status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_prepare_recovery_image_static_init (
	CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	uint32_t bytes = 50;
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock,
		handler.recovery.base.clear_recovery_image_region, &handler.recovery.base, 0,
		MOCK_ARG (bytes));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_execute_update_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.write_recovery_image_data,
		&handler.recovery.base, 0, MOCK_ARG_PTR_CONTAINS (image_data, sizeof (image_data)),
		MOCK_ARG (sizeof (image_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE;
	handler.context.buffer_length = sizeof (image_data);
	memcpy (handler.context.event_buffer, image_data, sizeof (image_data));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_update_recovery_image_failure (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_WRITE_FAIL,
		.arg1 = 1,
		.arg2 = RECOVERY_IMAGE_MANAGER_WRITE_FAILED
	};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	recovery_image_manager_set_port (&handler.recovery.base, 1);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.write_recovery_image_data,
		&handler.recovery.base, RECOVERY_IMAGE_MANAGER_WRITE_FAILED,
		MOCK_ARG_PTR_CONTAINS (image_data, sizeof (image_data)), MOCK_ARG (sizeof (image_data)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE;
	handler.context.buffer_length = sizeof (image_data);
	memcpy (handler.context.event_buffer, image_data, sizeof (image_data));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((RECOVERY_IMAGE_MANAGER_WRITE_FAILED & 0x00ffffff) << 8) |
			RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL),
		status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_update_recovery_image_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	uint8_t image_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.write_recovery_image_data,
		&handler.recovery.base, 0, MOCK_ARG_PTR_CONTAINS (image_data, sizeof (image_data)),
		MOCK_ARG (sizeof (image_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE;
	handler.context.buffer_length = sizeof (image_data);
	memcpy (handler.context.event_buffer, image_data, sizeof (image_data));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_execute_activate_recovery_image (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_ACTIVATING */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.activate_recovery_image,
		&handler.recovery.base, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_activate_recovery_image_failure (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_ACTIVATION_FAIL,
		.arg1 = 3,
		.arg2 = RECOVERY_IMAGE_MANAGER_ACTIVATE_FAILED
	};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	recovery_image_manager_set_port (&handler.recovery.base, 3);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_ACTIVATING */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.activate_recovery_image,
		&handler.recovery.base, RECOVERY_IMAGE_MANAGER_ACTIVATE_FAILED);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((RECOVERY_IMAGE_MANAGER_ACTIVATE_FAILED & 0x00ffffff) << 8) |
			RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL),
		status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_activate_recovery_image_static_init (
	CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	bool reset = false;

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_ACTIVATING */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.recovery.mock, handler.recovery.base.activate_recovery_image,
		&handler.recovery.base, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}

static void recovery_image_cmd_handler_test_execute_unknown_action (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 2,
		.arg2 = 0x10
	};

	TEST_START;

	recovery_image_cmd_handler_testing_init (test, &handler);

	recovery_image_manager_set_port (&handler.recovery.base, 2);

	handler.context.action = 0x10;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR),
		status);

	recovery_image_cmd_handler_testing_validate_and_release (test, &handler);
}

static void recovery_image_cmd_handler_test_execute_unknown_action_static_init (CuTest *test)
{
	struct recovery_image_cmd_handler_testing handler;
	struct recovery_image_cmd_handler test_static = recovery_image_cmd_handler_static_init (
		&handler.state, &handler.recovery.base, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RECOVERY,
		.msg_index = RECOVERY_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 3,
		.arg2 = 0x20
	};

	TEST_START;

	recovery_image_cmd_handler_testing_init_static (test, &handler, &test_static);

	handler.context.action = 0x20;

	recovery_image_manager_set_port (&handler.recovery.base, 3);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test,
		(((RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR),
		status);

	recovery_image_cmd_handler_testing_release_dependencies (test, &handler);
	recovery_image_cmd_handler_release (&test_static);
}


TEST_SUITE_START (recovery_image_cmd_handler);

TEST (recovery_image_cmd_handler_test_init);
TEST (recovery_image_cmd_handler_test_init_null);
TEST (recovery_image_cmd_handler_test_static_init);
TEST (recovery_image_cmd_handler_test_static_init_null);
TEST (recovery_image_cmd_handler_test_release_null);
TEST (recovery_image_cmd_handler_test_get_status);
TEST (recovery_image_cmd_handler_test_get_status_static_init);
TEST (recovery_image_cmd_handler_test_get_status_null);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_null);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_no_task);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_task_busy);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_get_context_error);
TEST (recovery_image_cmd_handler_test_prepare_recovery_image_notify_error);
TEST (recovery_image_cmd_handler_test_update_recovery_image);
TEST (recovery_image_cmd_handler_test_update_recovery_image_max_payload);
TEST (recovery_image_cmd_handler_test_update_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_update_recovery_image_null);
TEST (recovery_image_cmd_handler_test_update_recovery_image_too_much_data);
TEST (recovery_image_cmd_handler_test_update_recovery_image_no_task);
TEST (recovery_image_cmd_handler_test_update_recovery_image_task_busy);
TEST (recovery_image_cmd_handler_test_update_recovery_image_get_context_error);
TEST (recovery_image_cmd_handler_test_update_recovery_image_notify_error);
TEST (recovery_image_cmd_handler_test_activate_recovery_image);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_null);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_no_task);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_task_busy);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_get_context_error);
TEST (recovery_image_cmd_handler_test_activate_recovery_image_notify_error);
TEST (recovery_image_cmd_handler_test_execute_prepare_recovery_image);
TEST (recovery_image_cmd_handler_test_execute_prepare_recovery_image_failure);
TEST (recovery_image_cmd_handler_test_execute_prepare_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_execute_update_recovery_image);
TEST (recovery_image_cmd_handler_test_execute_update_recovery_image_failure);
TEST (recovery_image_cmd_handler_test_execute_update_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_execute_activate_recovery_image);
TEST (recovery_image_cmd_handler_test_execute_activate_recovery_image_failure);
TEST (recovery_image_cmd_handler_test_execute_activate_recovery_image_static_init);
TEST (recovery_image_cmd_handler_test_execute_unknown_action);
TEST (recovery_image_cmd_handler_test_execute_unknown_action_static_init);

TEST_SUITE_END;
