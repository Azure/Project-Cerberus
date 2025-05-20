// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/config_reset.h"
#include "firmware/authorized_execution_allow_impactful.h"
#include "firmware/authorized_execution_allow_impactful_static.h"
#include "firmware/firmware_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/firmware/impactful_update_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("authorized_execution_allow_impactful");


/**
 * Dependencies for testing.
 */
struct authorized_execution_allow_impactful_testing {
	struct impactful_update_mock impactful;				/**< Mock for impactful update management. */
	struct logging_mock log;							/**< Mock for debug logging. */
	struct authorized_execution_allow_impactful test;	/**< Authorized execution under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_allow_impactful_testing_init_dependencies (CuTest *test,
	struct authorized_execution_allow_impactful_testing *execution)
{
	int status;

	debug_log = NULL;

	status = impactful_update_mock_init (&execution->impactful);
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
static void authorized_execution_allow_impactful_testing_release_dependencies (CuTest *test,
	struct authorized_execution_allow_impactful_testing *execution)
{
	int status;

	debug_log = NULL;

	status = impactful_update_mock_validate_and_release (&execution->impactful);
	status |= logging_mock_validate_and_release (&execution->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an intrusion reset execution context for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 * @param auth_time The
 */
static void authorized_execution_allow_impactful_testing_init (CuTest *test,
	struct authorized_execution_allow_impactful_testing *execution, uint32_t auth_time)
{
	int status;

	authorized_execution_allow_impactful_testing_init_dependencies (test, execution);

	status = authorized_execution_allow_impactful_init (&execution->test,
		&execution->impactful.base, auth_time);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing components to release.
 */
static void authorized_execution_allow_impactful_testing_release (CuTest *test,
	struct authorized_execution_allow_impactful_testing *execution)
{
	authorized_execution_allow_impactful_release (&execution->test);

	authorized_execution_allow_impactful_testing_release_dependencies (test, execution);
}


/*******************
 * Test cases
 *******************/

static void authorized_execution_allow_impactful_test_init (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	status = authorized_execution_allow_impactful_init (&execution.test, &execution.impactful.base,
		auth_time);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_init_null (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	status = authorized_execution_allow_impactful_init (NULL, &execution.impactful.base, auth_time);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_allow_impactful_init (&execution.test, NULL, auth_time);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_allow_impactful_testing_release_dependencies (test, &execution);
}

static void authorized_execution_allow_impactful_test_static_init (CuTest *test)
{
	uint32_t auth_time = 200;
	struct authorized_execution_allow_impactful_testing execution = {
		.test = authorized_execution_allow_impactful_static_init (&execution.impactful.base,
			auth_time)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_execution_allow_impactful_release (NULL);
}

static void authorized_execution_allow_impactful_test_execute (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 150;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ALLOW_IMPACTFUL_UPDATE,
		.arg1 = auth_time,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = mock_expect (&execution.impactful.mock, execution.impactful.base.authorize_update,
		&execution.impactful, 0, MOCK_ARG (auth_time));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL, 0, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_execute_no_reset_req (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 1500;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ALLOW_IMPACTFUL_UPDATE,
		.arg1 = auth_time,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = mock_expect (&execution.impactful.mock, execution.impactful.base.authorize_update,
		&execution.impactful, 0, MOCK_ARG (auth_time));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_execute_static_init (CuTest *test)
{
	uint32_t auth_time = 5000;
	struct authorized_execution_allow_impactful_testing execution = {
		.test = authorized_execution_allow_impactful_static_init (&execution.impactful.base,
			auth_time)
	};
	bool reset_req = true;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ALLOW_IMPACTFUL_UPDATE,
		.arg1 = auth_time,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.impactful.mock, execution.impactful.base.authorize_update,
		&execution.impactful, 0, MOCK_ARG (auth_time));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL, 0, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, true, reset_req);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_execute_null (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	bool reset_req = false;
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = execution.test.base.execute (NULL, NULL, 0, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_execute_authorize_update_failure (
	CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_ALLOW_IMPACTFUL_FAIL,
		.arg1 = auth_time,
		.arg2 = IMPACTFUL_UPDATE_AUTHORIZE_FAILED
	};

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = mock_expect (&execution.impactful.mock, execution.impactful.base.authorize_update,
		&execution.impactful, IMPACTFUL_UPDATE_AUTHORIZE_FAILED, MOCK_ARG (auth_time));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL, 0, &reset_req);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_AUTHORIZE_FAILED, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_validate_data (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = execution.test.base.validate_data (&execution.test.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_validate_data_static_init (CuTest *test)
{
	uint32_t auth_time = 5000;
	struct authorized_execution_allow_impactful_testing execution = {
		.test = authorized_execution_allow_impactful_static_init (&execution.impactful.base,
			auth_time)
	};
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	status = execution.test.base.validate_data (&execution.test.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_validate_data_null (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	int status;

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	status = execution.test.base.validate_data (NULL, NULL, 0);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_get_status_identifiers (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_get_status_identifiers_static_init (
	CuTest *test)
{
	uint32_t auth_time = 100;
	struct authorized_execution_allow_impactful_testing execution = {
		.test = authorized_execution_allow_impactful_static_init (&execution.impactful.base,
			auth_time)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_allow_impactful_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}

static void authorized_execution_allow_impactful_test_get_status_identifiers_null (CuTest *test)
{
	struct authorized_execution_allow_impactful_testing execution;
	uint32_t auth_time = 100;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_allow_impactful_testing_init (test, &execution, auth_time);

	execution.test.base.get_status_identifiers (NULL, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	start = 0;
	error = 0;

	execution.test.base.get_status_identifiers (&execution.test.base, NULL, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, NULL);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);

	authorized_execution_allow_impactful_testing_release (test, &execution);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_execution_allow_impactful);

TEST (authorized_execution_allow_impactful_test_init);
TEST (authorized_execution_allow_impactful_test_init_null);
TEST (authorized_execution_allow_impactful_test_static_init);
TEST (authorized_execution_allow_impactful_test_release_null);
TEST (authorized_execution_allow_impactful_test_execute);
TEST (authorized_execution_allow_impactful_test_execute_no_reset_req);
TEST (authorized_execution_allow_impactful_test_execute_static_init);
TEST (authorized_execution_allow_impactful_test_execute_null);
TEST (authorized_execution_allow_impactful_test_execute_authorize_update_failure);
TEST (authorized_execution_allow_impactful_test_validate_data);
TEST (authorized_execution_allow_impactful_test_validate_data_static_init);
TEST (authorized_execution_allow_impactful_test_validate_data_null);
TEST (authorized_execution_allow_impactful_test_get_status_identifiers);
TEST (authorized_execution_allow_impactful_test_get_status_identifiers_static_init);
TEST (authorized_execution_allow_impactful_test_get_status_identifiers_null);

TEST_SUITE_END;
// *INDENT-ON*
