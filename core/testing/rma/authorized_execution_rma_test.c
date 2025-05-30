// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/config_reset.h"
#include "rma/authorized_execution_rma.h"
#include "rma/authorized_execution_rma_static.h"
#include "rma/rma_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/rma/device_rma_transition_mock.h"
#include "testing/mock/rma/rma_unlock_token_mock.h"
#include "testing/rma/secure_device_unlock_rma_testing.h"


TEST_SUITE_LABEL ("authorized_execution_rma");


/**
 * Dependencies for testing.
 */
struct authorized_execution_rma_testing {
	struct rma_unlock_token_mock token;		/**< Mock for the RMA token. */
	struct device_rma_transition_mock rma;	/**< Mock for the RMA stat transition. */
	struct logging_mock log;				/**< Mock for debug logging. */
	struct authorized_execution_rma test;	/**< Authorized execution under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_rma_testing_init_dependencies (CuTest *test,
	struct authorized_execution_rma_testing *execution)
{
	int status;

	debug_log = NULL;

	status = rma_unlock_token_mock_init (&execution->token);
	CuAssertIntEquals (test, 0, status);

	status = device_rma_transition_mock_init (&execution->rma);
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
static void authorized_execution_rma_testing_release_dependencies (CuTest *test,
	struct authorized_execution_rma_testing *execution)
{
	int status;

	debug_log = NULL;

	status = rma_unlock_token_mock_validate_and_release (&execution->token);
	status |= device_rma_transition_mock_validate_and_release (&execution->rma);
	status |= logging_mock_validate_and_release (&execution->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an RMA execution context for testing.
 *
 * @param test The testing framework.
 * @param execution The testing components to initialize.
 */
static void authorized_execution_rma_testing_init (CuTest *test,
	struct authorized_execution_rma_testing *execution)
{
	int status;

	authorized_execution_rma_testing_init_dependencies (test, execution);

	status = authorized_execution_rma_init (&execution->test, &execution->token.base,
		&execution->rma.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param execution The testing components to release.
 */
static void authorized_execution_rma_testing_release (CuTest *test,
	struct authorized_execution_rma_testing *execution)
{
	authorized_execution_rma_release (&execution->test);

	authorized_execution_rma_testing_release_dependencies (test, execution);
}


/*******************
 * Test cases
 *******************/

static void authorized_execution_rma_test_init (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	status = authorized_execution_rma_init (&execution.test, &execution.token.base,
		&execution.rma.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_init_null (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	status = authorized_execution_rma_init (NULL, &execution.token.base, &execution.rma.base);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_rma_init (&execution.test, NULL, &execution.rma.base);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	status = authorized_execution_rma_init (&execution.test, &execution.token.base, NULL);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_rma_testing_release_dependencies (test, &execution);
}

static void authorized_execution_rma_test_static_init (CuTest *test)
{
	struct authorized_execution_rma_testing execution = {
		.test = authorized_execution_rma_static_init (&execution.token.base, &execution.rma.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, execution.test.base.execute);
	CuAssertPtrNotNull (test, execution.test.base.validate_data);
	CuAssertPtrNotNull (test, execution.test.base.get_status_identifiers);

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_release_null (CuTest *test)
{
	TEST_START;

	authorized_execution_rma_release (NULL);
}

static void authorized_execution_rma_test_execute (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN,
		&reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_no_reset_req (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN, NULL);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_no_data (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	/* Null data pointer */
	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base, NULL,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	/* Zero data length */
	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN), MOCK_ARG (0));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, 0, &reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_static_init (CuTest *test)
{
	struct authorized_execution_rma_testing execution = {
		.test = authorized_execution_rma_static_init (&execution.token.base, &execution.rma.base)
	};
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_DONE,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma, 0);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN,
		&reset_req);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_null (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_FAILED,
		.arg1 = AUTHORIZED_EXECUTION_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (NULL, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN, &reset_req);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_invalid_token (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_FAILED,
		.arg1 = RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN,
		&reset_req);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_execute_config_rma_fail (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	bool reset_req = false;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_RMA,
		.msg_index = RMA_LOGGING_RMA_TRANSITION_FAILED,
		.arg1 = DEVICE_RMA_TRANSITION_CONFIG_FAIL,
		.arg2 = 0
	};

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	status |= mock_expect (&execution.rma.mock, execution.rma.base.config_rma, &execution.rma,
		DEVICE_RMA_TRANSITION_CONFIG_FAIL);

	status |= mock_expect (&execution.log.mock, execution.log.base.create_entry, &execution.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.execute (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN,
		&reset_req);
	CuAssertIntEquals (test, DEVICE_RMA_TRANSITION_CONFIG_FAIL, status);
	CuAssertIntEquals (test, false, reset_req);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_validate_data (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.validate_data (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_validate_data_no_data (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	/* Null data pointer. */
	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0, MOCK_ARG_PTR (NULL),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.validate_data (&execution.test.base, NULL,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Zero length data. */
	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.validate_data (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, 0);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_validate_data_static_init (CuTest *test)
{
	struct authorized_execution_rma_testing execution = {
		.test = authorized_execution_rma_static_init (&execution.token.base, &execution.rma.base)
	};
	int status;

	TEST_START;

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, 0,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.validate_data (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, 0, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_validate_data_null (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = execution.test.base.validate_data (NULL, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, AUTHORIZED_EXECUTION_INVALID_ARGUMENT, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_validate_data_invalid_token (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	int status;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	status = mock_expect (&execution.token.mock, execution.token.base.authenticate,
		&execution.token, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA,
		MOCK_ARG_PTR_CONTAINS (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN),
		MOCK_ARG (SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN));

	CuAssertIntEquals (test, 0, status);

	status = execution.test.base.validate_data (&execution.test.base,
		SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN, SECURE_DEVICE_UNLOCK_RMA_TESTING_TOKEN_LEN);
	CuAssertIntEquals (test, RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA, status);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_get_status_identifiers (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_get_status_identifiers_static_init (
	CuTest *test)
{
	struct authorized_execution_rma_testing execution = {
		.test = authorized_execution_rma_static_init (&execution.token.base, &execution.rma.base)
	};
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_rma_testing_init_dependencies (test, &execution);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	authorized_execution_rma_testing_release (test, &execution);
}

static void authorized_execution_rma_test_get_status_identifiers_null (CuTest *test)
{
	struct authorized_execution_rma_testing execution;
	uint8_t start;
	uint8_t error;

	TEST_START;

	authorized_execution_rma_testing_init (test, &execution);

	execution.test.base.get_status_identifiers (NULL, &start, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	start = 0;
	error = 0;

	execution.test.base.get_status_identifiers (&execution.test.base, NULL, &error);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED, error);

	execution.test.base.get_status_identifiers (&execution.test.base, &start, NULL);
	CuAssertIntEquals (test, CONFIG_RESET_STATUS_AUTHORIZED_OPERATION, start);

	authorized_execution_rma_testing_release (test, &execution);
}


// *INDENT-OFF*
TEST_SUITE_START (authorized_execution_rma);

TEST (authorized_execution_rma_test_init);
TEST (authorized_execution_rma_test_init_null);
TEST (authorized_execution_rma_test_static_init);
TEST (authorized_execution_rma_test_release_null);
TEST (authorized_execution_rma_test_execute);
TEST (authorized_execution_rma_test_execute_no_reset_req);
TEST (authorized_execution_rma_test_execute_no_data);
TEST (authorized_execution_rma_test_execute_static_init);
TEST (authorized_execution_rma_test_execute_null);
TEST (authorized_execution_rma_test_execute_invalid_token);
TEST (authorized_execution_rma_test_execute_config_rma_fail);
TEST (authorized_execution_rma_test_validate_data);
TEST (authorized_execution_rma_test_validate_data_no_data);
TEST (authorized_execution_rma_test_validate_data_static_init);
TEST (authorized_execution_rma_test_validate_data_null);
TEST (authorized_execution_rma_test_validate_data_invalid_token);
TEST (authorized_execution_rma_test_get_status_identifiers);
TEST (authorized_execution_rma_test_get_status_identifiers_static_init);
TEST (authorized_execution_rma_test_get_status_identifiers_null);

TEST_SUITE_END;
// *INDENT-ON*
