// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_cmd_handler.h"
#include "manifest/manifest_cmd_handler_static.h"
#include "manifest/manifest_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_cmd_handler_mock.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/system/event_task_mock.h"


TEST_SUITE_LABEL ("manifest_cmd_handler");


/**
 * Dependencies for testing.
 */
struct manifest_cmd_handler_testing {
	struct manifest_manager_mock manifest;		/**< Mock for the manifest manager. */
	struct logging_mock log;					/**< Mock for debug logging. */
	struct event_task_mock task;				/**< Mock for the command task. */
	struct event_task_context context;			/**< Event context for event processing. */
	struct event_task_context *context_ptr;		/**< Pointer to the event context. */
	struct manifest_cmd_handler_state state;	/**< Context for the manifest handler. */
	struct manifest_cmd_handler test;			/**< Manifest handler under test. */
	struct manifest_cmd_handler_mock test_mock;	/**< Mock manifest handler for testing. */
	bool is_mock;								/**< Flag indicating if the mock was initialized. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_testing_init_dependencies (CuTest *test,
	struct manifest_cmd_handler_testing *handler)
{
	int status;

	status = manifest_manager_mock_init (&handler->manifest);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	memset (&handler->context, 0, sizeof (handler->context));
	handler->context_ptr = &handler->context;

	debug_log = &handler->log.base;

	handler->is_mock = false;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_testing_init (CuTest *test,
	struct manifest_cmd_handler_testing *handler)
{
	int status;

	manifest_cmd_handler_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_init (&handler->test, &handler->state, &handler->manifest.base,
		&handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_testing_init_static (CuTest *test,
	struct manifest_cmd_handler_testing *handler, struct manifest_cmd_handler *test_static)
{
	int status;

	manifest_cmd_handler_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a mock instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param activate Enable the activation handler.
 */
static void manifest_cmd_handler_testing_init_mock (CuTest *test,
	struct manifest_cmd_handler_testing *handler, bool activate)
{
	int status;

	manifest_cmd_handler_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_mock_init (&handler->test_mock, &handler->state,
		&handler->manifest.base, &handler->task.base);
	CuAssertIntEquals (test, 0, status);

	if (activate) {
		manifest_cmd_handler_mock_enable_activation (&handler->test_mock);
	}

	handler->is_mock = true;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void manifest_cmd_handler_testing_release_dependencies (CuTest *test,
	struct manifest_cmd_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = manifest_manager_mock_validate_and_release (&handler->manifest);
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
static void manifest_cmd_handler_testing_validate_and_release (CuTest *test,
	struct manifest_cmd_handler_testing *handler)
{
	int status;

	manifest_cmd_handler_testing_release_dependencies (test, handler);

	if (!handler->is_mock) {
		manifest_cmd_handler_release (&handler->test);
	}
	else {
		status = manifest_cmd_handler_mock_validate_and_release (&handler->test_mock);
		CuAssertIntEquals (test, 0, status);
	}
}

/*******************
 * Test cases
 *******************/

static void manifest_cmd_handler_test_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base_cmd.prepare_manifest);
	CuAssertPtrNotNull (test, handler.test.base_cmd.store_manifest);
	CuAssertPtrNotNull (test, handler.test.base_cmd.finish_manifest);
	CuAssertPtrNotNull (test, handler.test.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base_event.prepare);
	CuAssertPtrNotNull (test, handler.test.base_event.execute);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_init_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_init (NULL, &handler.state, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_init (&handler.test, NULL, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_init (&handler.test, &handler.state, NULL, &handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_init (&handler.test, &handler.state, &handler.manifest.base,
		NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
}

static void manifest_cmd_handler_test_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.base_cmd.prepare_manifest);
	CuAssertPtrNotNull (test, test_static.base_cmd.store_manifest);
	CuAssertPtrNotNull (test, test_static.base_cmd.finish_manifest);
	CuAssertPtrNotNull (test, test_static.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, test_static.base_event.prepare);
	CuAssertPtrNotNull (test, test_static.base_event.execute);

	status = manifest_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_static_init_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_init_state (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = manifest_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = &handler.state;
	test_static.manifest = NULL;
	status = manifest_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.manifest = &handler.manifest.base;
	test_static.task = NULL;
	status = manifest_cmd_handler_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_cmd_handler_release (NULL);
}

static void manifest_cmd_handler_test_get_status (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_get_status_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_get_status_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.get_status (NULL);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_UNKNOWN, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_manifest (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_PREPARE, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	uint32_t bytes = 5000;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.prepare_manifest (&test_static.base_cmd, bytes);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_PREPARE, handler.context.action);
	CuAssertIntEquals (test, sizeof (bytes), handler.context.buffer_length);

	status = testing_validate_array ((uint8_t*) &bytes, handler.context.event_buffer,
		sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_prepare_manifest_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.prepare_manifest (NULL, bytes);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest_no_task (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_manifest (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_TASK_NOT_RUNNING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest_task_busy (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_manifest (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, MANIFEST_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest_get_context_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_manifest (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_prepare_manifest_notify_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 1000;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.prepare_manifest (&handler.test.base_cmd, bytes);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_STORE, handler.context.action);
	CuAssertIntEquals (test, sizeof (manifest_data), handler.context.buffer_length);

	status = testing_validate_array (manifest_data, handler.context.event_buffer,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_max_payload (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (manifest_data); i++) {
		manifest_data[i] = i;
	}

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_STORE, handler.context.action);
	CuAssertIntEquals (test, sizeof (manifest_data), handler.context.buffer_length);

	status = testing_validate_array (manifest_data, handler.context.event_buffer,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.store_manifest (&test_static.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_STORE, handler.context.action);
	CuAssertIntEquals (test, sizeof (manifest_data), handler.context.buffer_length);

	status = testing_validate_array (manifest_data, handler.context.event_buffer,
		sizeof (manifest_data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_store_manifest_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.store_manifest (NULL, manifest_data,	sizeof (manifest_data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, NULL,
		sizeof (manifest_data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_too_much_data (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[EVENT_TASK_CONTEXT_BUFFER_LENGTH + 1];

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_TOO_MUCH_DATA, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_no_task (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_TASK_NOT_RUNNING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_task_busy (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_get_context_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_store_manifest_notify_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.store_manifest (&handler.test.base_cmd, manifest_data,
		sizeof (manifest_data));
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_FINALIZE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_with_activation (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&handler.test.base_event));

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE,
		handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.finish_manifest (&test_static.base_cmd, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MANIFEST_CMD_HANDLER_ACTION_FINALIZE, handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_finish_manifest_static_init_with_activation (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task, 0,
		MOCK_ARG_PTR (&test_static.base_event));

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.finish_manifest (&test_static.base_cmd, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test,
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE,
		handler.context.action);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_STARTING, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_finish_manifest_null (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = handler.test.base_cmd.finish_manifest (NULL, false);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_no_task (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_NO_TASK, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, false);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NO_TASK, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_TASK_NOT_RUNNING, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_task_busy (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_BUSY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, false);
	CuAssertIntEquals (test, MANIFEST_MANAGER_TASK_BUSY, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_get_context_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	void *null_ptr = NULL;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);
	handler.context_ptr = NULL;

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task,
		EVENT_TASK_GET_CONTEXT_FAILED, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &null_ptr, sizeof (null_ptr), -1);

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, false);
	CuAssertIntEquals (test, EVENT_TASK_GET_CONTEXT_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_finish_manifest_notify_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.get_event_context, &handler.task, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.task.mock, 0, &handler.context_ptr,
		sizeof (handler.context_ptr), -1);

	status |= mock_expect (&handler.task.mock, handler.task.base.notify, &handler.task,
		EVENT_TASK_NOTIFY_FAILED, MOCK_ARG_PTR (&handler.test.base_event));

	/* Need to lock while updating the status. */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.finish_manifest (&handler.test.base_cmd, false);
	CuAssertIntEquals (test, EVENT_TASK_NOTIFY_FAILED, status);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_prepare_manifest (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 100;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: MANIFEST_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.clear_pending_region,
		&handler.manifest.base, 0, MOCK_ARG (bytes));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_prepare_manifest_failure (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint32_t bytes = 100;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_ERASE_FAIL,
		.arg1 = 2,
		.arg2 = MANIFEST_MANAGER_CLEAR_FAILED
	};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	manifest_manager_set_port (&handler.manifest.base, 2);

	/* Lock for state update: MANIFEST_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.clear_pending_region,
		&handler.manifest.base, MANIFEST_MANAGER_CLEAR_FAILED, MOCK_ARG (bytes));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_PREPARE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_CLEAR_FAILED & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_PREPARE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_prepare_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	uint32_t bytes = 50;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: MANIFEST_CMD_STATUS_PREPARE */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.clear_pending_region,
		&handler.manifest.base, 0, MOCK_ARG (bytes));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_PREPARE;
	handler.context.buffer_length = sizeof (bytes);
	memcpy (handler.context.event_buffer, &bytes, sizeof (bytes));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_execute_store_manifest (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	/* Lock for state update: MANIFEST_CMD_STATUS_STORE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.write_pending_data,
		&handler.manifest.base, 0, MOCK_ARG_PTR_CONTAINS (manifest_data, sizeof (manifest_data)),
		MOCK_ARG (sizeof (manifest_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_STORE;
	handler.context.buffer_length = sizeof (manifest_data);
	memcpy (handler.context.event_buffer, manifest_data, sizeof (manifest_data));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_store_manifest_failure (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15};
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_WRITE_FAIL,
		.arg1 = 1,
		.arg2 = MANIFEST_MANAGER_WRITE_FAILED
	};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	manifest_manager_set_port (&handler.manifest.base, 1);

	/* Lock for state update: MANIFEST_CMD_STATUS_STORE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.write_pending_data,
		&handler.manifest.base, MANIFEST_MANAGER_WRITE_FAILED,
		MOCK_ARG_PTR_CONTAINS (manifest_data, sizeof (manifest_data)),
		MOCK_ARG (sizeof (manifest_data)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_STORE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_STORE;
	handler.context.buffer_length = sizeof (manifest_data);
	memcpy (handler.context.event_buffer, manifest_data, sizeof (manifest_data));

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_WRITE_FAILED & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_STORE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_store_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	uint8_t manifest_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: MANIFEST_CMD_STATUS_STORE_DATA */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.write_pending_data,
		&handler.manifest.base, 0, MOCK_ARG_PTR_CONTAINS (manifest_data, sizeof (manifest_data)),
		MOCK_ARG (sizeof (manifest_data)));

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_STORE;
	handler.context.buffer_length = sizeof (manifest_data);
	memcpy (handler.context.event_buffer, manifest_data, sizeof (manifest_data));

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_no_activation (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_no_activation_has_pending (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_VERIFY_FAIL,
		.arg1 = 0,
		.arg2 = MANIFEST_MANAGER_HAS_PENDING
	};

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_HAS_PENDING);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_HAS_PENDING & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_VALIDATE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_no_activation_none_pending (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_VERIFY_FAIL,
		.arg1 = 0,
		.arg2 = MANIFEST_MANAGER_NONE_PENDING
	};

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_NONE_PENDING);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_NONE_PENDING & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_VALIDATE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_no_activation_failure (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_VERIFY_FAIL,
		.arg1 = 0,
		.arg2 = MANIFEST_MANAGER_VERIFY_FAILED
	};

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_VERIFY_FAILED);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_VERIFY_FAILED & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_VALIDATE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATING */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.test_mock.mock, handler.test_mock.base.activation,
		&handler.test_mock, 0, MOCK_ARG_NOT_NULL);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_set_reset (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	bool set_reset = true;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATING */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.test_mock.mock, handler.test_mock.base.activation,
		&handler.test_mock, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.test_mock.mock, 0, &set_reset, sizeof (set_reset), -1);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 1, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_has_pending (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_HAS_PENDING);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATING */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.test_mock.mock, handler.test_mock.base.activation,
		&handler.test_mock, 0, MOCK_ARG_NOT_NULL);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_none_pending (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_NONE_PENDING);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATING */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.test_mock.mock, handler.test_mock.base.activation,
		&handler.test_mock, 0, MOCK_ARG_NOT_NULL);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_failure (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_VERIFY_FAIL,
		.arg1 = 0,
		.arg2 = MANIFEST_MANAGER_VERIFY_FAILED
	};

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, MANIFEST_MANAGER_VERIFY_FAILED);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATE_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test,
		(((MANIFEST_MANAGER_VERIFY_FAILED & 0x00ffffff) << 8) | MANIFEST_CMD_STATUS_VALIDATE_FAIL),
		status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_no_handler (
	CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, false);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATION_FAIL */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, (((MANIFEST_MANAGER_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_ACTIVATION_FAIL), status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_with_activation_error (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_mock (test, &handler, true);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: MANIFEST_CMD_STATUS_ACTIVATING */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.test_mock.mock, handler.test_mock.base.activation,
		&handler.test_mock, MANIFEST_MANAGER_ACTIVATE_FAILED, MOCK_ARG_NOT_NULL);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action =
		MANIFEST_CMD_HANDLER_ACTION_FINALIZE | MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;

	handler.test_mock.base.base_event.execute (&handler.test_mock.base.base_event,
		handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	/* Base instance just reports raw status from the activation function call. */
	status = handler.test_mock.base.base_cmd.get_status (&handler.test_mock.base.base_cmd);
	CuAssertIntEquals (test, MANIFEST_MANAGER_ACTIVATE_FAILED, status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_finalize_manifest_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	bool reset = false;

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	/* Lock for state update: MANIFEST_CMD_STATUS_VALIDATION */
	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.verify_pending_manifest,
		&handler.manifest.base, 0);

	/* Lock for state update: 0 */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.context.action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}

static void manifest_cmd_handler_test_execute_unknown_action (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 2,
		.arg2 = 0x10
	};

	TEST_START;

	manifest_cmd_handler_testing_init (test, &handler);

	manifest_manager_set_port (&handler.manifest.base, 2);

	handler.context.action = 0x10;

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	handler.test.base_event.execute (&handler.test.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base_cmd.get_status (&handler.test.base_cmd);
	CuAssertIntEquals (test, (((MANIFEST_MANAGER_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_INTERNAL_ERROR), status);

	manifest_cmd_handler_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_test_execute_unknown_action_static_init (CuTest *test)
{
	struct manifest_cmd_handler_testing handler;
	struct manifest_cmd_handler test_static = manifest_cmd_handler_static_init (&handler.state,
		&handler.manifest.base, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_NOTIFICATION_ERROR,
		.arg1 = 3,
		.arg2 = 0x20
	};

	TEST_START;

	manifest_cmd_handler_testing_init_static (test, &handler, &test_static);

	handler.context.action = 0x20;

	manifest_manager_set_port (&handler.manifest.base, 3);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	/* Lock for state update: MANIFEST_CMD_STATUS_INTERNAL_ERROR */
	status |= mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	test_static.base_event.execute (&test_static.base_event, handler.context_ptr, &reset);
	CuAssertIntEquals (test, 0, reset);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base_cmd.get_status (&test_static.base_cmd);
	CuAssertIntEquals (test, (((MANIFEST_MANAGER_UNSUPPORTED_OP & 0x00ffffff) << 8) |
			MANIFEST_CMD_STATUS_INTERNAL_ERROR), status);

	manifest_cmd_handler_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_release (&test_static);
}


// *INDENT-OFF*
TEST_SUITE_START (manifest_cmd_handler);

TEST (manifest_cmd_handler_test_init);
TEST (manifest_cmd_handler_test_init_null);
TEST (manifest_cmd_handler_test_static_init);
TEST (manifest_cmd_handler_test_static_init_null);
TEST (manifest_cmd_handler_test_release_null);
TEST (manifest_cmd_handler_test_get_status);
TEST (manifest_cmd_handler_test_get_status_static_init);
TEST (manifest_cmd_handler_test_get_status_null);
TEST (manifest_cmd_handler_test_prepare_manifest);
TEST (manifest_cmd_handler_test_prepare_manifest_static_init);
TEST (manifest_cmd_handler_test_prepare_manifest_null);
TEST (manifest_cmd_handler_test_prepare_manifest_no_task);
TEST (manifest_cmd_handler_test_prepare_manifest_task_busy);
TEST (manifest_cmd_handler_test_prepare_manifest_get_context_error);
TEST (manifest_cmd_handler_test_prepare_manifest_notify_error);
TEST (manifest_cmd_handler_test_store_manifest);
TEST (manifest_cmd_handler_test_store_manifest_max_payload);
TEST (manifest_cmd_handler_test_store_manifest_static_init);
TEST (manifest_cmd_handler_test_store_manifest_null);
TEST (manifest_cmd_handler_test_store_manifest_too_much_data);
TEST (manifest_cmd_handler_test_store_manifest_no_task);
TEST (manifest_cmd_handler_test_store_manifest_task_busy);
TEST (manifest_cmd_handler_test_store_manifest_get_context_error);
TEST (manifest_cmd_handler_test_store_manifest_notify_error);
TEST (manifest_cmd_handler_test_finish_manifest);
TEST (manifest_cmd_handler_test_finish_manifest_with_activation);
TEST (manifest_cmd_handler_test_finish_manifest_static_init);
TEST (manifest_cmd_handler_test_finish_manifest_static_init_with_activation);
TEST (manifest_cmd_handler_test_finish_manifest_null);
TEST (manifest_cmd_handler_test_finish_manifest_no_task);
TEST (manifest_cmd_handler_test_finish_manifest_task_busy);
TEST (manifest_cmd_handler_test_finish_manifest_get_context_error);
TEST (manifest_cmd_handler_test_finish_manifest_notify_error);
TEST (manifest_cmd_handler_test_execute_prepare_manifest);
TEST (manifest_cmd_handler_test_execute_prepare_manifest_failure);
TEST (manifest_cmd_handler_test_execute_prepare_manifest_static_init);
TEST (manifest_cmd_handler_test_execute_store_manifest);
TEST (manifest_cmd_handler_test_execute_store_manifest_failure);
TEST (manifest_cmd_handler_test_execute_store_manifest_static_init);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_no_activation);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_no_activation_has_pending);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_no_activation_none_pending);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_no_activation_failure);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_set_reset);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_has_pending);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_none_pending);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_failure);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_no_handler);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_with_activation_error);
TEST (manifest_cmd_handler_test_execute_finalize_manifest_static_init);
TEST (manifest_cmd_handler_test_execute_unknown_action);
TEST (manifest_cmd_handler_test_execute_unknown_action_static_init);

TEST_SUITE_END;
// *INDENT-ON*
