// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/security_manager.h"
#include "system/system_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/security_manager_mock.h"
#include "testing/mock/system/security_policy_mock.h"


TEST_SUITE_LABEL ("security_manager");


/**
 * Global instance for the default security policy.
 */
static struct security_policy_mock default_policy_mock;

const struct security_policy *const default_policy = &default_policy_mock.base;


/**
 * Dependencies for testing.
 */
struct security_manager_testing {
	struct logging_mock logger;			/**< Mock for debug logging. */
	struct security_policy_mock policy;	/**< Mock for the default policy. */
	struct security_manager_mock test;	/**< Mock for the security manager to use for testing. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 */
static void security_manager_testing_init_dependencies (CuTest *test,
	struct security_manager_testing *manager)
{
	int status;

	status = logging_mock_init (&manager->logger);
	CuAssertIntEquals (test, 0, status);

	status = security_policy_mock_init (&default_policy_mock);
	CuAssertIntEquals (test, 0, status);

	status = security_policy_mock_init (&manager->policy);
	CuAssertIntEquals (test, 0, status);

	status = security_manager_mock_init (&manager->test);
	CuAssertIntEquals (test, 0, status);

	debug_log = &manager->logger.base;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void security_manager_testing_release_dependencies (CuTest *test,
	struct security_manager_testing *manager)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&manager->logger);
	status |= security_policy_mock_validate_and_release (&default_policy_mock);
	status |= security_policy_mock_validate_and_release (&manager->policy);
	status |= security_manager_mock_validate_and_release (&manager->test);

	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void security_manager_test_get_security_policy_use_default (CuTest *test)
{
	struct security_manager_testing manager;
	void *no_policy = NULL;
	int status;
	const struct security_policy *policy;

	TEST_START;

	security_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.test.mock, manager.test.base.internal.get_security_policy,
		&manager.test, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.test.mock, 0, &no_policy, sizeof (no_policy), -1);

	CuAssertIntEquals (test, 0, status);

	policy = security_manager_get_security_policy (&manager.test.base);
	CuAssertPtrEquals (test, &default_policy_mock, (void*) policy);

	security_manager_testing_release_dependencies (test, &manager);
}

static void security_manager_test_get_security_policy_use_active (CuTest *test)
{
	struct security_manager_testing manager;
	struct security_policy active_policy;
	void *with_policy = &active_policy;
	int status;
	const struct security_policy *policy;

	TEST_START;

	security_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.test.mock, manager.test.base.internal.get_security_policy,
		&manager.test, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&manager.test.mock, 0, &with_policy, sizeof (with_policy), -1);

	CuAssertIntEquals (test, 0, status);

	policy = security_manager_get_security_policy (&manager.test.base);
	CuAssertPtrEquals (test, &active_policy, (void*) policy);

	security_manager_testing_release_dependencies (test, &manager);
}

static void security_manager_test_get_security_policy_null (CuTest *test)
{
	struct security_manager_testing manager;
	int status;
	const struct security_policy *policy;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_GET_POLICY_FAIL,
		.arg1 = SECURITY_MANAGER_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	security_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.logger.mock, manager.logger.base.create_entry, &manager.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	policy = security_manager_get_security_policy (NULL);
	CuAssertPtrEquals (test, &default_policy_mock, (void*) policy);

	security_manager_testing_release_dependencies (test, &manager);
}

static void security_manager_test_get_security_policy_error (CuTest *test)
{
	struct security_manager_testing manager;
	int status;
	const struct security_policy *policy;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_GET_POLICY_FAIL,
		.arg1 = SECURITY_MANAGER_GET_POLICY_FAILED,
		.arg2 = 0
	};

	TEST_START;

	security_manager_testing_init_dependencies (test, &manager);

	status = mock_expect (&manager.test.mock, manager.test.base.internal.get_security_policy,
		&manager.test, SECURITY_MANAGER_GET_POLICY_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&manager.logger.mock, manager.logger.base.create_entry, &manager.logger,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	policy = security_manager_get_security_policy (&manager.test.base);
	CuAssertPtrEquals (test, &default_policy_mock, (void*) policy);

	security_manager_testing_release_dependencies (test, &manager);
}


// *INDENT-OFF*
TEST_SUITE_START (security_manager);

TEST (security_manager_test_get_security_policy_use_default);
TEST (security_manager_test_get_security_policy_use_active);
TEST (security_manager_test_get_security_policy_null);
TEST (security_manager_test_get_security_policy_error);

TEST_SUITE_END;
// *INDENT-ON*
