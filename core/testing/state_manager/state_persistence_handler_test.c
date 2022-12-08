// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "flash/flash_common.h"
#include "state_manager/state_logging.h"
#include "state_manager/state_persistence_handler.h"
#include "state_manager/state_persistence_handler_static.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/logging/debug_log_testing.h"


TEST_SUITE_LABEL ("state_persistence_handler");


/**
 * Dependencies for testing.
 */
struct state_persistence_handler_testing {
	struct flash_mock flash1;						/**< Mock for the state flash. */
	struct state_manager manager1;					/**< State manager for testing. */
	struct flash_mock flash2;						/**< Mock for the state flash. */
	struct state_manager manager2;					/**< State manager for testing. */
	struct flash_mock flash3;						/**< Mock for the state flash. */
	struct state_manager manager3;					/**< State manager for testing. */
	struct logging_mock log;						/**< Mock for debug logging. */
	struct state_persistence_handler_state state;	/**< Context for the test being tested. */
	struct state_persistence_handler test;			/**< Log flush task for testing. */
};


/**
 * Initialize a state manager.
 *
 * @param test The testing framework.
 * @param flash Flash used by the state manager.
 * @param manager The state manager to initialize.
 *
 */
static void state_persistence_handler_testing_init_state_manager (CuTest *test,
	struct flash_mock *flash, struct state_manager *manager)
{
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	status = mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&flash->mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output_tmp (&flash->mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output_tmp (&flash->mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = state_manager_init (manager, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void state_persistence_handler_testing_init_dependencies (CuTest *test,
	struct state_persistence_handler_testing *handler)
{
	int status;

	status = flash_mock_init (&handler->flash1);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->flash1.mock, "flash1");

	status = flash_mock_init (&handler->flash2);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->flash2.mock, "flash2");

	status = flash_mock_init (&handler->flash3);
	CuAssertIntEquals (test, 0, status);
	mock_set_name (&handler->flash3.mock, "flash3");

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	state_persistence_handler_testing_init_state_manager (test, &handler->flash1,
		&handler->manager1);
	state_persistence_handler_testing_init_state_manager (test, &handler->flash2,
		&handler->manager2);
	state_persistence_handler_testing_init_state_manager (test, &handler->flash3,
		&handler->manager3);

	debug_log = &handler->log.base;
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param manager_list List of state managers to use with the handler.
 * @param manager_count Number of state managers in the list.
 * @param period_ms Time between handler executions.
 */
static void state_persistence_handler_testing_init (CuTest *test,
	struct state_persistence_handler_testing *handler, struct state_manager **manager_list,
	size_t manager_count, uint32_t period_ms)
{
	int status;

	state_persistence_handler_testing_init_dependencies (test, handler);

	status = state_persistence_handler_init (&handler->test, &handler->state, manager_list,
		manager_count, period_ms);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static, instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 * @param test_static The static handler to initialize.
 */
static void state_persistence_handler_testing_init_static (CuTest *test,
	struct state_persistence_handler_testing *handler,
	struct state_persistence_handler *test_static)
{
	int status;

	state_persistence_handler_testing_init_dependencies (test, handler);

	status = state_persistence_handler_init_state (test_static);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void state_persistence_handler_testing_release_dependencies (CuTest *test,
	struct state_persistence_handler_testing *handler)
{
	int status;

	debug_log = NULL;

	status = flash_mock_validate_and_release (&handler->flash1);
	status |= flash_mock_validate_and_release (&handler->flash2);
	status |= flash_mock_validate_and_release (&handler->flash3);
	status |= logging_mock_validate_and_release (&handler->log);

	CuAssertIntEquals (test, 0, status);

	state_manager_release (&handler->manager1);
	state_manager_release (&handler->manager2);
	state_manager_release (&handler->manager3);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void state_persistence_handler_testing_validate_and_release (CuTest *test,
	struct state_persistence_handler_testing *handler)
{
	state_persistence_handler_testing_release_dependencies (test, handler);
	state_persistence_handler_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void state_persistence_handler_test_init (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	state_persistence_handler_testing_init_dependencies (test, &handler);

	status = state_persistence_handler_init (&handler.test, &handler.state, list, count, 100);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.test.base.prepare);
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_init_null (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	int status;

	TEST_START;

	state_persistence_handler_testing_init_dependencies (test, &handler);

	status = state_persistence_handler_init (NULL, &handler.state, list, count, 100);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = state_persistence_handler_init (&handler.test, NULL, list, count, 100);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = state_persistence_handler_init (&handler.test, &handler.state, NULL, count, 100);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = state_persistence_handler_init (&handler.test, &handler.state, list, 0, 100);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	state_persistence_handler_testing_release_dependencies(test, &handler);
}

static void state_persistence_handler_test_static_init (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	struct state_persistence_handler test_static = state_persistence_handler_static_init (
		&handler.state, list, count, 500);
	int status;

	TEST_START;

	state_persistence_handler_testing_init_dependencies (test, &handler);

	CuAssertPtrNotNull (test, test_static.base.prepare);
	CuAssertPtrNotNull (test, test_static.base.get_next_execution);
	CuAssertPtrNotNull (test, test_static.base.execute);

	status = state_persistence_handler_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	state_persistence_handler_testing_release_dependencies (test, &handler);
	state_persistence_handler_release (&test_static);
}

static void state_persistence_handler_test_static_init_null (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	struct state_persistence_handler test_static = state_persistence_handler_static_init (
		&handler.state, list, count, 500);
	int status;

	TEST_START;

	state_persistence_handler_testing_init_dependencies (test, &handler);

	status = state_persistence_handler_init_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = state_persistence_handler_init_state (&test_static);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	test_static.state = &handler.state;
	test_static.managers = NULL;
	status = state_persistence_handler_init_state (&test_static);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	test_static.managers = list;
	test_static.manager_count = 0;
	status = state_persistence_handler_init_state (&test_static);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	state_persistence_handler_testing_release_dependencies (test, &handler);
}

static void state_persistence_handler_test_release_null (CuTest *test)
{
	TEST_START;

	state_persistence_handler_release (NULL);
}

static void state_persistence_handler_test_get_next_execution (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	handler.test.base.prepare (&handler.test.base);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > 950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_get_next_execution_no_prepare (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_get_next_execution_static_init (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	struct state_persistence_handler test_static = state_persistence_handler_static_init (
		&handler.state, list, count, 5000);
	const platform_clock *next_time;
	uint32_t msec;
	int status;

	TEST_START;

	state_persistence_handler_testing_init_static (test, &handler, &test_static);

	test_static.base.prepare (&test_static.base);

	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 5000));
	CuAssertTrue (test, (msec > 4950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_release_dependencies (test, &handler);
	state_persistence_handler_release (&test_static);
}

static void state_persistence_handler_test_execute (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	status = mock_expect (&handler.flash1.mock, handler.flash1.base.get_sector_size,
		&handler.flash1, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash1.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash1.mock, handler.flash1.base.write, &handler.flash1,
		sizeof (expected), MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&handler.flash1, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	/* Force a change to the state that will be stored. */
	handler.manager1.nv_state = 0xfffe;

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > 950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_execute_failure (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_STATE_MGR,
		.msg_index = STATE_LOGGING_PERSIST_FAIL,
		.arg1 = 0,
		.arg2 = FLASH_SECTOR_SIZE_FAILED
	};

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	status = mock_expect (&handler.flash1.mock, handler.flash1.base.get_sector_size,
		&handler.flash1, FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	/* Force a change to the state that will be stored. */
	handler.manager1.nv_state = 0xfffe;

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > 950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_execute_multiple_managers (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	/* manager1 */
	status = mock_expect (&handler.flash1.mock, handler.flash1.base.get_sector_size,
		&handler.flash1, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash1.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash1.mock, handler.flash1.base.write, &handler.flash1,
		sizeof (expected), MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&handler.flash1, 0x11000, 0x1000);

	/* manager2 */
	status |= mock_expect (&handler.flash2.mock, handler.flash2.base.get_sector_size,
		&handler.flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash2.mock, handler.flash2.base.write, &handler.flash2,
		sizeof (expected), MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&handler.flash2, 0x11000, 0x1000);

	/* manager3 */
	status |= mock_expect (&handler.flash3.mock, handler.flash3.base.get_sector_size,
		&handler.flash3, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash3.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash3.mock, handler.flash3.base.write, &handler.flash3,
		sizeof (expected), MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&handler.flash3, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	/* Force a change to the state that will be stored. */
	handler.manager1.nv_state = 0xfffe;
	handler.manager2.nv_state = 0xfffe;
	handler.manager3.nv_state = 0xfffe;

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > 950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_execute_multiple_managers_failure (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1, &handler.manager2, &handler.manager3};
	const size_t count = sizeof (list) / sizeof (list[0]);
	const platform_clock *next_time;
	uint32_t msec;
	int status;
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_STATE_MGR,
		.msg_index = STATE_LOGGING_PERSIST_FAIL,
		.arg1 = 0,
		.arg2 = FLASH_SECTOR_SIZE_FAILED
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_STATE_MGR,
		.msg_index = STATE_LOGGING_PERSIST_FAIL,
		.arg1 = 1,
		.arg2 = FLASH_SECTOR_SIZE_FAILED
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_STATE_MGR,
		.msg_index = STATE_LOGGING_PERSIST_FAIL,
		.arg1 = 2,
		.arg2 = FLASH_WRITE_FAILED
	};

	TEST_START;

	state_persistence_handler_testing_init (test, &handler, list, count, 1000);

	status = mock_expect (&handler.flash1.mock, handler.flash1.base.get_sector_size,
		&handler.flash1, FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	status |= mock_expect (&handler.flash2.mock, handler.flash2.base.get_sector_size,
		&handler.flash2, FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	status |= mock_expect (&handler.flash3.mock, handler.flash3.base.get_sector_size,
		&handler.flash3, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash3.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash3.mock, handler.flash3.base.write, &handler.flash3,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)), MOCK_ARG (sizeof (expected)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	handler.test.base.prepare (&handler.test.base);
	platform_msleep (200);

	/* Force a change to the state that will be stored. */
	handler.manager1.nv_state = 0xfffe;
	handler.manager2.nv_state = 0xfffe;
	handler.manager3.nv_state = 0xfffe;

	handler.test.base.execute (&handler.test.base);

	/* Check the the timeout has been updated. */
	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 1000));
	CuAssertTrue (test, (msec > 950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_validate_and_release (test, &handler);
}

static void state_persistence_handler_test_execute_static_init (CuTest *test)
{
	struct state_persistence_handler_testing handler;
	struct state_manager *list[] = {&handler.manager1};
	const size_t count = sizeof (list) / sizeof (list[0]);
	struct state_persistence_handler test_static = state_persistence_handler_static_init (
		&handler.state, list, count, 5000);
	const platform_clock *next_time;
	uint32_t msec;
	int status;
	uint16_t expected[4] = {0xffbe, 0xffbe, 0xffbe, 0};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	state_persistence_handler_testing_init_static (test, &handler, &test_static);

	status = mock_expect (&handler.flash1.mock, handler.flash1.base.get_sector_size,
		&handler.flash1, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&handler.flash1.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&handler.flash1.mock, handler.flash1.base.write, &handler.flash1,
		sizeof (expected), MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&expected, sizeof (expected)),
		MOCK_ARG (sizeof (expected)));

	status |= flash_mock_expect_erase_flash_sector_verify (&handler.flash1, 0x11000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	/* Create initial timeout. */
	test_static.base.prepare (&test_static.base);
	platform_msleep (200);

	/* Force a change to the state that will be stored. */
	handler.manager1.nv_state = 0xfffe;
	handler.manager2.nv_state = 0xfffe;
	handler.manager3.nv_state = 0xfffe;

	test_static.base.execute (&test_static.base);

	/* Check the the timeout has been updated. */
	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrNotNull (test, (void*) next_time);

	status = platform_get_timeout_remaining (next_time, &msec);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test, (msec <= 5000));
	CuAssertTrue (test, (msec > 4950));	/* Apply reasonable bounds for testing. */

	state_persistence_handler_testing_release_dependencies (test, &handler);
	state_persistence_handler_release (&test_static);
}


TEST_SUITE_START (state_persistence_handler);

TEST (state_persistence_handler_test_init);
TEST (state_persistence_handler_test_init_null);
TEST (state_persistence_handler_test_static_init);
TEST (state_persistence_handler_test_static_init_null);
TEST (state_persistence_handler_test_release_null);
TEST (state_persistence_handler_test_get_next_execution);
TEST (state_persistence_handler_test_get_next_execution_no_prepare);
TEST (state_persistence_handler_test_get_next_execution_static_init);
TEST (state_persistence_handler_test_execute);
TEST (state_persistence_handler_test_execute_failure);
TEST (state_persistence_handler_test_execute_multiple_managers);
TEST (state_persistence_handler_test_execute_multiple_managers_failure);
TEST (state_persistence_handler_test_execute_static_init);

TEST_SUITE_END;
