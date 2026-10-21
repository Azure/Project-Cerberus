// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "firmware/firmware_logging.h"
#include "firmware/impactful_update.h"
#include "firmware/impactful_update_static.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/firmware/impactful_check_mock.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("impactful_update");


/**
 * Dependencies for testing.
 */
struct impactful_update_testing {
	struct impactful_check_mock check[4];			/**< Mocks for impactful checks. */
	const struct impactful_check *check_list[4];	/**< List of impactful checks. */
	struct logging_mock log;						/**< Mock for debug logging. */
	struct impactful_update_state state;			/**< Context for the update manager. */
	struct impactful_update test;					/**< Update manager under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param impactful The testing components to initialize.
 */
static void impactful_update_testing_init_dependencies (CuTest *test,
	struct impactful_update_testing *impactful)
{
	int status;

	status = impactful_check_mock_init (&impactful->check[0]);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&impactful->check[0].mock, "impactful_check[0]");

	status = impactful_check_mock_init (&impactful->check[1]);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&impactful->check[1].mock, "impactful_check[1]");

	status = impactful_check_mock_init (&impactful->check[2]);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&impactful->check[2].mock, "impactful_check[2]");

	status = impactful_check_mock_init (&impactful->check[3]);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&impactful->check[3].mock, "impactful_check[3]");

	impactful->check_list[0] = &impactful->check[0].base;
	impactful->check_list[1] = &impactful->check[1].base;
	impactful->check_list[2] = &impactful->check[2].base;
	impactful->check_list[3] = &impactful->check[3].base;

	status = logging_mock_init (&impactful->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &impactful->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param impactful The testing dependencies to release.
 */
static void impactful_update_testing_release_dependencies (CuTest *test,
	struct impactful_update_testing *impactful)
{
	size_t i;
	int status = 0;

	debug_log = NULL;

	for (i = 0; i < ARRAY_SIZE (impactful->check); i++) {
		status |= impactful_check_mock_validate_and_release (&impactful->check[i]);
	}
	status |= logging_mock_validate_and_release (&impactful->log);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param impactful The testing components to initialize.
 * @param check_count The number of impactful checks to use.
 */
static void impactful_update_testing_init (CuTest *test, struct impactful_update_testing *impactful,
	size_t check_count)
{
	int status;

	impactful_update_testing_init_dependencies (test, impactful);

	status = impactful_update_init (&impactful->test, &impactful->state, impactful->check_list,
		check_count);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The testing framework.
 * @param impactful The testing components to initialize.
 */
static void impactful_update_testing_init_static (CuTest *test,
	struct impactful_update_testing *impactful)
{
	int status;

	impactful_update_testing_init_dependencies (test, impactful);

	status = impactful_update_init_state (&impactful->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param impactful The testing components to release.
 */
static void impactful_update_testing_release (CuTest *test,
	struct impactful_update_testing *impactful)
{
	impactful_update_release (&impactful->test);
	impactful_update_testing_release_dependencies (test, impactful);
}


/*******************
 * Test cases
 *******************/

static void impactful_update_test_init (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init_dependencies (test, &impactful);

	status = impactful_update_init (&impactful.test, &impactful.state, impactful.check_list, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, impactful.test.base.is_update_not_impactful);
	CuAssertPtrNotNull (test, impactful.test.base.is_update_allowed);
	CuAssertPtrNotNull (test, impactful.test.base.authorize_update);
	CuAssertPtrNotNull (test, impactful.test.base.reset_authorization);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_init_null (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init_dependencies (test, &impactful);

	status = impactful_update_init (NULL, &impactful.state, impactful.check_list, 1);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init (&impactful.test, NULL, impactful.check_list, 1);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init (&impactful.test, &impactful.state, NULL, 1);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init (&impactful.test, &impactful.state, impactful.check_list, 0);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release_dependencies (test, &impactful);
}

static void impactful_update_test_static_init (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 1)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, impactful.test.base.is_update_not_impactful);
	CuAssertPtrNotNull (test, impactful.test.base.is_update_allowed);
	CuAssertPtrNotNull (test, impactful.test.base.authorize_update);
	CuAssertPtrNotNull (test, impactful.test.base.reset_authorization);

	impactful_update_testing_init_dependencies (test, &impactful);

	status = impactful_update_init_state (&impactful.test);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_static_init_null (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 1)
	};
	struct impactful_update null_state = impactful_update_static_init (NULL, impactful.check_list,
		1);
	struct impactful_update null_list = impactful_update_static_init (&impactful.state, NULL, 1);
	struct impactful_update zero_count = impactful_update_static_init (&impactful.state,
		impactful.check_list, 0);
	int status;

	TEST_START;

	impactful_update_testing_init_dependencies (test, &impactful);

	status = impactful_update_init_state (NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init_state (&null_state);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init_state (&null_list);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	status = impactful_update_init_state (&zero_count);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release_dependencies (test, &impactful);
}

static void impactful_update_test_release_null (CuTest *test)
{
	TEST_START;

	impactful_update_release (NULL);
}

static void impactful_update_test_is_update_not_impactful_check_not_impactful (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_check_impactful (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_multiple_check_not_impactful (
	CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 3);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);
	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_multiple_check_impactful (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 3);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_check_not_impactful_static_init (
	CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 4)
	};
	int status;

	TEST_START;

	impactful_update_testing_init_static (test, &impactful);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);
	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], 0);
	status |= mock_expect (&impactful.check[3].mock, impactful.check[3].base.is_not_impactful,
		&impactful.check[3], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_check_impactful_static_init (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 4)
	};
	int status;

	TEST_START;

	impactful_update_testing_init_static (test, &impactful);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);
	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_null (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.is_update_not_impactful (NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_not_impactful_check_error (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 4);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);
	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_not_impactful (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_not_impactful (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_impactful_auth_allowed (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_impactful_auth_blocked (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_BLOCKED,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_AUTH_NOT_ALLOWED
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0],
		IMPACTFUL_CHECK_AUTH_NOT_ALLOWED);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_AUTH_NOT_ALLOWED, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_multiple_check_not_impactful (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 3);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);
	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_multiple_check_impactful_auth_allowed (
	CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 1,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 3,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 4);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);

	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], 0);

	status |= mock_expect (&impactful.check[3].mock, impactful.check[3].base.is_not_impactful,
		&impactful.check[3], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[3].mock,
		impactful.check[3].base.is_authorization_allowed, &impactful.check[3], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_multiple_check_impactful_auth_blocked (
	CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 1,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_BLOCKED,
		.arg1 = 2,
		.arg2 = IMPACTFUL_CHECK_AUTH_NOT_ALLOWED
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 4);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);

	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[2].mock,
		impactful.check[2].base.is_authorization_allowed, &impactful.check[2],
		IMPACTFUL_CHECK_AUTH_NOT_ALLOWED);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_AUTH_NOT_ALLOWED, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_static_init (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 2)
	};
	int status;

	TEST_START;

	impactful_update_testing_init_static (test, &impactful);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_null (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.is_update_allowed (NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_check_error (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 1,
		.arg2 = IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 3);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);
	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	status |= mock_expect (&impactful.check[2].mock, impactful.check[2].base.is_not_impactful,
		&impactful.check[2], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_NOT_IMPACTFUL_FAILED, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_is_update_allowed_auth_allowed_error (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_WARNING,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_BLOCKED,
		.arg1 = 1,
		.arg2 = IMPACTFUL_CHECK_AUTH_ALLOWED_FAILED
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 4);

	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], 0);

	status |= mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1],
		IMPACTFUL_CHECK_AUTH_ALLOWED_FAILED);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_AUTH_ALLOWED_FAILED, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_no_expiration (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_with_expiration (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_authorization_expired (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (150);

	/* Verify that an impactful update authorization is no longer valid. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_second_authorization (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	/* First authorization received. */
	status = impactful.test.base.authorize_update (&impactful.test.base, 100);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (150);

	/* Verify that an impactful update authorization is no longer valid. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	/* Second authorization received. */
	status = impactful.test.base.authorize_update (&impactful.test.base, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_authorization_refresh (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 200);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	status = impactful.test.base.authorize_update (&impactful.test.base, 1000);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_authorization_remove_expiration (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 200);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	status = impactful.test.base.authorize_update (&impactful.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (200);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_static_init (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 2)
	};
	int status;

	TEST_START;

	impactful_update_testing_init_static (test, &impactful);

	status = impactful.test.base.authorize_update (&impactful.test.base, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (100);

	/* Verify that an impactful update is now authorized. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status = mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1], 0);

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_authorize_update_null (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (NULL, 500);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_reset_authorization_no_expiration (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.reset_authorization (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	/* Verify that an impactful update authorization is no longer valid. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_reset_authorization_with_expiration (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.authorize_update (&impactful.test.base, 500);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	status = impactful.test.base.reset_authorization (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	/* Verify that an impactful update authorization is no longer valid. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_reset_authorization_static_init (CuTest *test)
{
	struct impactful_update_testing impactful = {
		.test = impactful_update_static_init (&impactful.state, impactful.check_list, 2)
	};
	int status;
	struct debug_log_entry_info entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 0,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_CERBERUS_FW,
		.msg_index = FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,
		.arg1 = 1,
		.arg2 = IMPACTFUL_CHECK_IMPACTFUL_UPDATE
	};

	TEST_START;

	impactful_update_testing_init_static (test, &impactful);

	status = impactful.test.base.authorize_update (&impactful.test.base, 500);
	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.reset_authorization (&impactful.test.base);
	CuAssertIntEquals (test, 0, status);

	platform_msleep (50);

	/* Verify that an impactful update authorization is no longer valid. */
	status = mock_expect (&impactful.check[0].mock, impactful.check[0].base.is_not_impactful,
		&impactful.check[0], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[0].mock,
		impactful.check[0].base.is_authorization_allowed, &impactful.check[0], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry0)));

	status = mock_expect (&impactful.check[1].mock, impactful.check[1].base.is_not_impactful,
		&impactful.check[1], IMPACTFUL_CHECK_IMPACTFUL_UPDATE);
	status |= mock_expect (&impactful.check[1].mock,
		impactful.check[1].base.is_authorization_allowed, &impactful.check[1], 0);

	status |= mock_expect (&impactful.log.mock, impactful.log.base.create_entry, &impactful.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	status = impactful.test.base.is_update_allowed (&impactful.test.base);
	CuAssertIntEquals (test, IMPACTFUL_CHECK_IMPACTFUL_UPDATE, status);

	impactful_update_testing_release (test, &impactful);
}

static void impactful_update_test_reset_authorization_null (CuTest *test)
{
	struct impactful_update_testing impactful;
	int status;

	TEST_START;

	impactful_update_testing_init (test, &impactful, 1);

	status = impactful.test.base.reset_authorization (NULL);
	CuAssertIntEquals (test, IMPACTFUL_UPDATE_INVALID_ARGUMENT, status);

	impactful_update_testing_release (test, &impactful);
}


// *INDENT-OFF*
TEST_SUITE_START (impactful_update);

TEST (impactful_update_test_init);
TEST (impactful_update_test_init_null);
TEST (impactful_update_test_static_init);
TEST (impactful_update_test_static_init_null);
TEST (impactful_update_test_release_null);
TEST (impactful_update_test_is_update_not_impactful_check_not_impactful);
TEST (impactful_update_test_is_update_not_impactful_check_impactful);
TEST (impactful_update_test_is_update_not_impactful_multiple_check_not_impactful);
TEST (impactful_update_test_is_update_not_impactful_multiple_check_impactful);
TEST (impactful_update_test_is_update_not_impactful_check_not_impactful_static_init);
TEST (impactful_update_test_is_update_not_impactful_check_impactful_static_init);
TEST (impactful_update_test_is_update_not_impactful_null);
TEST (impactful_update_test_is_update_not_impactful_check_error);
TEST (impactful_update_test_is_update_allowed_not_impactful);
TEST (impactful_update_test_is_update_allowed_impactful_auth_allowed);
TEST (impactful_update_test_is_update_allowed_impactful_auth_blocked);
TEST (impactful_update_test_is_update_allowed_multiple_check_not_impactful);
TEST (impactful_update_test_is_update_allowed_multiple_check_impactful_auth_allowed);
TEST (impactful_update_test_is_update_allowed_multiple_check_impactful_auth_blocked);
TEST (impactful_update_test_is_update_allowed_static_init);
TEST (impactful_update_test_is_update_allowed_null);
TEST (impactful_update_test_is_update_allowed_check_error);
TEST (impactful_update_test_is_update_allowed_auth_allowed_error);
TEST (impactful_update_test_authorize_update_no_expiration);
TEST (impactful_update_test_authorize_update_with_expiration);
TEST (impactful_update_test_authorize_update_authorization_expired);
TEST (impactful_update_test_authorize_update_second_authorization);
TEST (impactful_update_test_authorize_update_authorization_refresh);
TEST (impactful_update_test_authorize_update_authorization_remove_expiration);
TEST (impactful_update_test_authorize_update_static_init);
TEST (impactful_update_test_authorize_update_null);
TEST (impactful_update_test_reset_authorization_no_expiration);
TEST (impactful_update_test_reset_authorization_with_expiration);
TEST (impactful_update_test_reset_authorization_static_init);
TEST (impactful_update_test_reset_authorization_null);

TEST_SUITE_END;
// *INDENT-ON*
