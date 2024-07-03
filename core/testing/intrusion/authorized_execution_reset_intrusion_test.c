// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_logging.h"
#include "cmd_interface/config_reset.h"
#include "intrusion/authorized_execution_reset_intrusion.h"
#include "intrusion/authorized_execution_reset_intrusion_static.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/intrusion/intrusion_manager_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("authorized_execution_reset_intrusion");


/**
 * Dependencies for testing.
 */
struct authorized_execution_reset_intrusion_testing {
	struct intrusion_manager_mock intrusion;			/**< Mock for intrusion state management. */
	struct logging_mock log;							/**< Mock for debug logging. */
	struct authorized_execution_reset_intrusion test;	/**< Authorized execution under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_reset_intrusion_testing_init_dependencies (CuTest *test,
	struct authorized_execution_reset_intrusion_testing *execution)
{
	int status;

	debug_log = NULL;

	status = intrusion_manager_mock_init (&execution->intrusion);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&execution->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &execution->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing dependencies to release.
 */
static void authorized_execution_reset_intrusion_testing_release_dependencies (CuTest *test,
	struct authorized_execution_reset_intrusion_testing *execution)
{
	int status;

	debug_log = NULL;

	status = intrusion_manager_mock_validate_and_release (&execution->intrusion);
	status |= logging_mock_validate_and_release (&execution->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an intrusion reset execution context for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_reset_intrusion_testing_init (CuTest *test,
	struct authorized_execution_reset_intrusion_testing *execution)
{
	int status;

	authorized_execution_reset_intrusion_testing_init_dependencies (test, execution);

	status = authorized_execution_reset_intrusion_init (&execution->test,
		&execution->intrusion.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing components to release.
 */
static void authorized_execution_reset_intrusion_testing_release (CuTest *test,
	struct authorized_execution_reset_intrusion_testing *execution)
{
	authorized_execution_reset_intrusion_release (&execution->test);

	authorized_execution_reset_intrusion_testing_release_dependencies (test, execution);
}


/*******************
 * Test cases
 *******************/

static void authorized_execution_reset_intrusion_test_init (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	int status;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init_dependencies (test, &execution);

	status = authorized_execution_reset_intrusion_init (&execution.test, &execution.intrusion.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_init_null (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	int status;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init_dependencies (test, &execution);

	status = authorized_execution_reset_intrusion_init (NULL, &execution.intrusion.base);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_reset_intrusion_init (&execution.test, NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_reset_intrusion_testing_release_dependencies (test, &execution);
}

static void authorized_execution_reset_intrusion_test_static_init (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution = {
		.test = authorized_execution_reset_intrusion_static_init (&execution.intrusion.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_reset_intrusion_testing_init_dependencies (test, &execution);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_execution_reset_intrusion_release (NULL);
}

static void authorized_execution_reset_intrusion_test_execute_reset_intrusion (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_RESET_INTRUSION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_reset_intrusion_testing_init (test, &execution);

	status = mock_expect (&execution.intrusion.mock, execution.intrusion.base.reset_intrusion,
		&execution.intrusion, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_execute_reset_intrusion_static_init (
	CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution = {
		.test = authorized_execution_reset_intrusion_static_init (&execution.intrusion.base)
	};
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_RESET_INTRUSION,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_reset_intrusion_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.intrusion.mock, execution.intrusion.base.reset_intrusion,
		&execution.intrusion, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_execute_null (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	int status;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init (test, &execution);

	status = execution.test.base.execute (NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_execute_reset_intrusion_failure (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_RESET_INTRUSION_FAIL,
		.arg1 = INTRUSION_MANAGER_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_reset_intrusion_testing_init (test, &execution);

	status = mock_expect (&execution.intrusion.mock, execution.intrusion.base.reset_intrusion,
		&execution.intrusion, INTRUSION_MANAGER_RESET_FAILED);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base);
	CuAssertIntEquals (test, INTRUSION_MANAGER_RESET_FAILED, status);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_get_status_identifiers (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESET_INTRUSION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_INTRUSION_FAILED, error);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_get_status_identifiers_static_init (
	CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution = {
		.test = authorized_execution_reset_intrusion_static_init (&execution.intrusion.base)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESET_INTRUSION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_INTRUSION_FAILED, error);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}

static void authorized_execution_reset_intrusion_test_get_status_identifiers_null (CuTest *test)
{
	struct authorized_execution_reset_intrusion_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_reset_intrusion_testing_init (test, &execution);

	execution.test.base.get_status_identifiers (NULL, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESET_INTRUSION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_INTRUSION_FAILED, error);

	start = 0;
	error = 0;

	execution.test.base.get_status_identifiers (&execution.test.base, NULL, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_INTRUSION_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, NULL);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_RESET_INTRUSION, start);

	authorized_execution_reset_intrusion_testing_release (test, &execution);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_execution_reset_intrusion);

TEST (authorized_execution_reset_intrusion_test_init);
TEST (authorized_execution_reset_intrusion_test_init_null);
TEST (authorized_execution_reset_intrusion_test_static_init);
TEST (authorized_execution_reset_intrusion_test_release_null);
TEST (authorized_execution_reset_intrusion_test_execute_reset_intrusion);
TEST (authorized_execution_reset_intrusion_test_execute_reset_intrusion_static_init);
TEST (authorized_execution_reset_intrusion_test_execute_null);
TEST (authorized_execution_reset_intrusion_test_execute_reset_intrusion_failure);
TEST (authorized_execution_reset_intrusion_test_get_status_identifiers);
TEST (authorized_execution_reset_intrusion_test_get_status_identifiers_static_init);
TEST (authorized_execution_reset_intrusion_test_get_status_identifiers_null);

TEST_SUITE_END;
// *INDENT-ON*
