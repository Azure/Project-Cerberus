// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "system/system.h"
#include "system/system_logging.h"
#include "testing/mock/cmd_interface/cmd_device_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/system_observer_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("system");


/**
 * Dependencies for testing.
 */
struct system_testing {
	struct cmd_device_mock device;			/**< Mock for device hardware. */
	struct system_observer_mock observer;	/**< Mock for a system observer. */
	struct logging_mock logger;				/**< Mock for debug logging. */
	struct system test;						/**< System manager under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param sytem The testing components to initialize.
 */
static void system_testing_init_dependencies (CuTest *test, struct system_testing *system)
{
	int status;

	status = cmd_device_mock_init (&system->device);
	CuAssertIntEquals (test, 0, status);

	status = system_observer_mock_init (&system->observer);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&system->logger);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param cfm The testing components to release.
 */
static void system_testing_validate_and_release_dependencies (CuTest *test,
	struct system_testing *system)
{
	int status;

	debug_log = NULL;

	status = cmd_device_mock_validate_and_release (&system->device);
	CuAssertIntEquals (test, 0, status);

	status = system_observer_mock_validate_and_release (&system->observer);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_validate_and_release (&system->logger);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Fully initialize an system instance for testing.
 *
 * @param test The testing framework.
 * @param system The testing components to initialize.
 */
static void system_testing_init (CuTest *test, struct system_testing *system)
{
	int status;

	system_testing_init_dependencies (test, system);

	status = system_init (&system->test, &system->device.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param system The testing components to release.
 */
static void system_testing_validate_and_release (CuTest *test, struct system_testing *system)
{
	system_release (&system->test);

	system_testing_validate_and_release_dependencies (test, system);
}


/*******************
 * Test cases
 *******************/

static void system_test_init (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init_dependencies (test, &system);

	status = system_init (&system.test, &system.device.base);
	CuAssertIntEquals (test, 0, status);

	system_testing_validate_and_release (test, &system);
}

static void system_test_init_null (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init_dependencies (test, &system);

	status = system_init (NULL, &system.device.base);
	CuAssertIntEquals (test, SYSTEM_INVALID_ARGUMENT, status);

	status = system_init (&system.test, NULL);
	CuAssertIntEquals (test, SYSTEM_INVALID_ARGUMENT, status);

	system_testing_validate_and_release_dependencies (test, &system);
}

static void system_test_release_null (CuTest *test)
{
	TEST_START;

	system_release (NULL);
}

static void system_test_add_observer (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init (test, &system);

	status = system_add_observer (&system.test, &system.observer.base);
	CuAssertIntEquals (test, 0, status);

	system_testing_validate_and_release (test, &system);
}

static void system_test_add_observer_null (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init (test, &system);

	status = system_add_observer (NULL, &system.observer.base);
	CuAssertIntEquals (test, SYSTEM_INVALID_ARGUMENT, status);

	status = system_add_observer (&system.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	system_testing_validate_and_release (test, &system);
}

static void system_test_remove_observer (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init (test, &system);

	status = system_remove_observer (&system.test, &system.observer.base);
	CuAssertIntEquals (test, 0, status);

	system_testing_validate_and_release (test, &system);
}

static void system_test_remove_observer_null (CuTest *test)
{
	struct system_testing system;
	int status;

	TEST_START;

	system_testing_init (test, &system);

	status = system_remove_observer (NULL, &system.observer.base);
	CuAssertIntEquals (test, SYSTEM_INVALID_ARGUMENT, status);

	status = system_remove_observer (&system.test, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	system_testing_validate_and_release (test, &system);
}

static void system_test_reset (CuTest *test)
{
	struct system_testing system;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_RESET_FAIL,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	system_testing_init (test, &system);

	status = system_add_observer (&system.test, &system.observer.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = &system.logger.base;

	status = mock_expect (&system.observer.mock, system.observer.base.on_shutdown, &system.observer,
		0);
	status |= mock_expect (&system.logger.mock, system.logger.base.flush, &system.logger, 0);
	status |= mock_expect (&system.device.mock, system.device.base.reset, &system.device, 0);

	status |= mock_expect (&system.logger.mock, system.logger.base.create_entry, &system.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	system_reset (&system.test);

	system_testing_validate_and_release (test, &system);
}

static void system_test_reset_no_observers (CuTest *test)
{
	struct system_testing system;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_RESET_FAIL,
		.arg1 = 0,
		.arg2 = 0
	};

	TEST_START;

	system_testing_init (test, &system);

	debug_log = &system.logger.base;

	status = mock_expect (&system.logger.mock, system.logger.base.flush, &system.logger, 0);
	status |= mock_expect (&system.device.mock, system.device.base.reset, &system.device, 0);

	status |= mock_expect (&system.logger.mock, system.logger.base.create_entry, &system.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	system_reset (&system.test);

	system_testing_validate_and_release (test, &system);
}

static void system_test_reset_null (CuTest *test)
{
	struct system_testing system;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_RESET_NOT_EXECUTED,
		.arg1 = SYSTEM_INVALID_ARGUMENT,
		.arg2 = 0
	};

	TEST_START;

	system_testing_init (test, &system);

	debug_log = &system.logger.base;

	status = mock_expect (&system.logger.mock, system.logger.base.create_entry, &system.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	system_reset (NULL);

	system_testing_validate_and_release (test, &system);
}

static void system_test_reset_device_reset_error (CuTest *test)
{
	struct system_testing system;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SYSTEM,
		.msg_index = SYSTEM_LOGGING_RESET_FAIL,
		.arg1 = CMD_DEVICE_RESET_FAILED,
		.arg2 = 0
	};

	TEST_START;

	system_testing_init (test, &system);

	status = system_add_observer (&system.test, &system.observer.base);
	CuAssertIntEquals (test, 0, status);

	debug_log = &system.logger.base;

	status = mock_expect (&system.observer.mock, system.observer.base.on_shutdown, &system.observer,
		0);
	status |= mock_expect (&system.logger.mock, system.logger.base.flush, &system.logger, 0);
	status |= mock_expect (&system.device.mock, system.device.base.reset, &system.device,
		CMD_DEVICE_RESET_FAILED);

	status |= mock_expect (&system.logger.mock, system.logger.base.create_entry, &system.logger, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	system_reset (&system.test);

	system_testing_validate_and_release (test, &system);
}


TEST_SUITE_START (system);

TEST (system_test_init);
TEST (system_test_init_null);
TEST (system_test_release_null);
TEST (system_test_add_observer);
TEST (system_test_add_observer_null);
TEST (system_test_remove_observer);
TEST (system_test_remove_observer_null);
TEST (system_test_reset);
TEST (system_test_reset_no_observers);
TEST (system_test_reset_null);
TEST (system_test_reset_device_reset_error);

TEST_SUITE_END;
