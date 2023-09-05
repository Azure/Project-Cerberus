// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/security_policy.h"
#include "system/system_logging.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/security_policy_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("security_policy");


/**
 * Dependencies for testing.
 */
struct security_policy_testing {
	struct logging_mock logger;				/**< Mock for debug logging. */
	struct security_policy_mock test;		/**< Mock for the security policy to use for testing. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param policy The testing components to initialize.
 */
static void security_policy_testing_init_dependencies (CuTest *test,
	struct security_policy_testing *policy)
{
	int status;

	status = logging_mock_init (&policy->logger);
	CuAssertIntEquals (test, 0, status);

	status = security_policy_mock_init (&policy->test);
	CuAssertIntEquals (test, 0, status);

	debug_log = &policy->logger.base;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param policy The testing components to release.
 */
static void security_policy_testing_release_dependencies (CuTest *test,
	struct security_policy_testing *policy)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&policy->logger);
	status |= security_policy_mock_validate_and_release (&policy->test);

	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void security_policy_test_enforce_firmware_signing (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_firmware_signing,
		&policy.test, 1);
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_firmware_signing (&policy.test.base);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_firmware_signing_not_enforcing (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_firmware_signing,
		&policy.test, 0);
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_firmware_signing (&policy.test.base);
	CuAssertIntEquals (test, false, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_firmware_signing_null (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_POLICY_CHECK_FAIL,
		.arg1 = SYSTEM_LOGGING_POLICY_FW_SIGNING,
		.arg2 = SECURITY_POLICY_INVALID_ARGUMENT
	};

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.logger.mock, policy.logger.base.create_entry, &policy.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_firmware_signing (NULL);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_firmware_signing_check_error (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_POLICY_CHECK_FAIL,
		.arg1 = SYSTEM_LOGGING_POLICY_FW_SIGNING,
		.arg2 = SECURITY_POLICY_FW_SIGNING_CHECK_FAILED
	};

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_firmware_signing,
		&policy.test, SECURITY_POLICY_FW_SIGNING_CHECK_FAILED);

	status |= mock_expect (&policy.logger.mock, policy.logger.base.create_entry, &policy.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_firmware_signing (&policy.test.base);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_anti_rollback (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_anti_rollback,
		&policy.test, 1);
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_anti_rollback (&policy.test.base);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_anti_rollback_not_enforcing (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_anti_rollback,
		&policy.test, 0);
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_anti_rollback (&policy.test.base);
	CuAssertIntEquals (test, false, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_anti_rollback_null (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_POLICY_CHECK_FAIL,
		.arg1 = SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,
		.arg2 = SECURITY_POLICY_INVALID_ARGUMENT
	};

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.logger.mock, policy.logger.base.create_entry, &policy.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_anti_rollback (NULL);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}

static void security_policy_test_enforce_anti_rollback_check_error (CuTest *test)
{
	struct security_policy_testing policy;
	int status;
	bool enforce;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_POLICY_CHECK_FAIL,
		.arg1 = SYSTEM_LOGGING_POLICY_ANTI_ROLLBACK,
		.arg2 = SECURITY_POLICY_ANTI_ROLLBACK_CHECK_FAILED
	};

	TEST_START;

	security_policy_testing_init_dependencies (test, &policy);

	status = mock_expect (&policy.test.mock, policy.test.base.enforce_anti_rollback,
		&policy.test, SECURITY_POLICY_ANTI_ROLLBACK_CHECK_FAILED);

	status |= mock_expect (&policy.logger.mock, policy.logger.base.create_entry, &policy.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	enforce = security_policy_enforce_anti_rollback (&policy.test.base);
	CuAssertIntEquals (test, true, enforce);

	security_policy_testing_release_dependencies (test, &policy);
}


TEST_SUITE_START (security_policy);

TEST (security_policy_test_enforce_firmware_signing);
TEST (security_policy_test_enforce_firmware_signing_not_enforcing);
TEST (security_policy_test_enforce_firmware_signing_null);
TEST (security_policy_test_enforce_firmware_signing_check_error);
TEST (security_policy_test_enforce_anti_rollback);
TEST (security_policy_test_enforce_anti_rollback_not_enforcing);
TEST (security_policy_test_enforce_anti_rollback_null);
TEST (security_policy_test_enforce_anti_rollback_check_error);

TEST_SUITE_END;
