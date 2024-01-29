// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/manifest_logging.h"
#include "manifest/cfm/manifest_cmd_handler_cfm.h"
#include "manifest/cfm/manifest_cmd_handler_cfm_static.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/manifest/manifest_manager_mock.h"
#include "testing/mock/system/event_task_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("manifest_cmd_handler_cfm");


/**
 * Dependencies for testing.
 */
struct manifest_cmd_handler_cfm_testing {
	struct manifest_manager_mock manifest;		/**< Mock for the manifest manager. */
	struct logging_mock log;					/**< Mock for debug logging. */
	struct event_task_mock task;				/**< Mock for the command task. */
	struct manifest_cmd_handler_state state;	/**< Context for the manifest handler. */
	struct manifest_cmd_handler_cfm test;		/**< Manifest handler under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_cfm_testing_init_dependencies (CuTest *test,
	struct manifest_cmd_handler_cfm_testing *handler)
{
	int status;

	status = manifest_manager_mock_init (&handler->manifest);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	status = event_task_mock_init (&handler->task);
	CuAssertIntEquals (test, 0, status);

	debug_log = &handler->log.base;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_cfm_testing_init (CuTest *test,
	struct manifest_cmd_handler_cfm_testing *handler)
{
	int status;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_cfm_init (&handler->test, &handler->state,
		&handler->manifest.base, &handler->task.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void manifest_cmd_handler_cfm_testing_init_static (CuTest *test,
	struct manifest_cmd_handler_cfm_testing *handler, struct manifest_cmd_handler_cfm *test_static)
{
	int status;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, handler);

	status = manifest_cmd_handler_cfm_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void manifest_cmd_handler_cfm_testing_release_dependencies (CuTest *test,
	struct manifest_cmd_handler_cfm_testing *handler)
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
static void manifest_cmd_handler_cfm_testing_validate_and_release (CuTest *test,
	struct manifest_cmd_handler_cfm_testing *handler)
{
	manifest_cmd_handler_cfm_testing_release_dependencies (test, handler);
	manifest_cmd_handler_cfm_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void manifest_cmd_handler_cfm_test_init (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_cfm_init (&handler.test, &handler.state, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, 0, status);

	/* The base API will not be overridden and does not need to be tested. */
	CuAssertPtrEquals (test, manifest_cmd_handler_prepare_manifest,
		handler.test.base.base_cmd.prepare_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_store_manifest,
		handler.test.base.base_cmd.store_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_finish_manifest,
		handler.test.base.base_cmd.finish_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_get_status,
		handler.test.base.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, handler.test.base.base_event.prepare);
	CuAssertPtrEquals (test, manifest_cmd_handler_execute, handler.test.base.base_event.execute);

	CuAssertPtrNotNull (test, handler.test.base.activation);

	manifest_cmd_handler_cfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_cfm_test_init_null (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_cfm_init (NULL, &handler.state, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_cfm_init (&handler.test, NULL, &handler.manifest.base,
		&handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_cfm_init (&handler.test, &handler.state, NULL,
		&handler.task.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manifest_cmd_handler_cfm_init (&handler.test, &handler.state, &handler.manifest.base,
		NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_cfm_testing_release_dependencies (test, &handler);
}

static void manifest_cmd_handler_cfm_test_static_init (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	struct manifest_cmd_handler_cfm test_static = manifest_cmd_handler_cfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, &handler);

	/* The base API will not be overridden and does not need to be tested. */
	CuAssertPtrEquals (test, manifest_cmd_handler_prepare_manifest,
		test_static.base.base_cmd.prepare_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_store_manifest,
		test_static.base.base_cmd.store_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_finish_manifest,
		test_static.base.base_cmd.finish_manifest);
	CuAssertPtrEquals (test, manifest_cmd_handler_get_status, test_static.base.base_cmd.get_status);

	CuAssertPtrEquals (test, NULL, test_static.base.base_event.prepare);
	CuAssertPtrEquals (test, manifest_cmd_handler_execute, test_static.base.base_event.execute);

	CuAssertPtrNotNull (test, test_static.base.activation);

	status = manifest_cmd_handler_cfm_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	manifest_cmd_handler_cfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_cfm_release (&test_static);
}

static void manifest_cmd_handler_cfm_test_static_init_null (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	struct manifest_cmd_handler_cfm test_static = manifest_cmd_handler_cfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_dependencies (test, &handler);

	status = manifest_cmd_handler_cfm_init_state (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.state = NULL;
	status = manifest_cmd_handler_cfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.state = &handler.state;
	test_static.base.manifest = NULL;
	status = manifest_cmd_handler_cfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	test_static.base.manifest = &handler.manifest.base;
	test_static.base.task = NULL;
	status = manifest_cmd_handler_cfm_init_state (&test_static);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	manifest_cmd_handler_cfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_cfm_release (&test_static);
}

static void manifest_cmd_handler_cfm_test_release_null (CuTest *test)
{
	TEST_START;

	manifest_cmd_handler_cfm_release (NULL);
}

static void manifest_cmd_handler_cfm_test_get_status (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init (test, &handler);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.base_cmd.get_status (&handler.test.base.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_cfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_cfm_test_get_status_static_init (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	struct manifest_cmd_handler_cfm test_static = manifest_cmd_handler_cfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base);
	int status;

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.task.mock, handler.task.base.lock, &handler.task, 0);
	status |= mock_expect (&handler.task.mock, handler.task.base.unlock, &handler.task, 0);

	CuAssertIntEquals (test, 0, status);

	status = test_static.base.base_cmd.get_status (&test_static.base.base_cmd);
	CuAssertIntEquals (test, MANIFEST_CMD_STATUS_NONE_STARTED, status);

	manifest_cmd_handler_cfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_cfm_release (&test_static);
}

static void manifest_cmd_handler_cfm_test_activation (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_CFM_ACTIVATION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	manifest_cmd_handler_cfm_testing_init (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.activate_pending_manifest,
		&handler.manifest, 0);
	CuAssertIntEquals (test, 0, status);

	status = handler.test.base.activation (&handler.test.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_cfm_testing_validate_and_release (test, &handler);
}

static void manifest_cmd_handler_cfm_test_activation_static_init (CuTest *test)
{
	struct manifest_cmd_handler_cfm_testing handler;
	struct manifest_cmd_handler_cfm test_static = manifest_cmd_handler_cfm_static_init (
		&handler.state, &handler.manifest.base, &handler.task.base);
	int status;
	bool reset = false;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MANIFEST,
		.msg_index = MANIFEST_LOGGING_CFM_ACTIVATION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	manifest_cmd_handler_cfm_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&handler.manifest.mock, handler.manifest.base.activate_pending_manifest,
		&handler.manifest, 0);
	CuAssertIntEquals (test, 0, status);

	status = test_static.base.activation (&test_static.base, &reset);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, reset);

	manifest_cmd_handler_cfm_testing_release_dependencies (test, &handler);
	manifest_cmd_handler_cfm_release (&test_static);
}


TEST_SUITE_START (manifest_cmd_handler_cfm);

TEST (manifest_cmd_handler_cfm_test_init);
TEST (manifest_cmd_handler_cfm_test_init_null);
TEST (manifest_cmd_handler_cfm_test_static_init);
TEST (manifest_cmd_handler_cfm_test_static_init_null);
TEST (manifest_cmd_handler_cfm_test_release_null);
TEST (manifest_cmd_handler_cfm_test_get_status);
TEST (manifest_cmd_handler_cfm_test_get_status_static_init);
TEST (manifest_cmd_handler_cfm_test_activation);
TEST (manifest_cmd_handler_cfm_test_activation_static_init);

TEST_SUITE_END;
