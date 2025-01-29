// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "logging/crash_dump_logging.h"
#include "logging/debug_log.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/mock/system/real_time_clock_mock.h"


TEST_SUITE_LABEL ("crash_dump_logging");


/**
 * Dependencies for testing.
 */
struct crash_dump_logging_testing {
	struct logging_mock log;	/**< Mock for debug logging. */
	uint32_t data[100];			/**< Data under test. */
	size_t data_length;			/**< Length of data under test. */
};


/**
 * Helper function to setup the crash dump logging for testing.
 *
 * @param test The test framework.
 * @param handler The testing components to initialize.
 */
static void crash_dump_logging_testing_init_dependencies (CuTest *test,
	struct crash_dump_logging_testing *handler)
{
	int status;

	status = logging_mock_init (&handler->log);
	CuAssertIntEquals (test, 0, status);

	memset (handler->data, 0, sizeof (handler->data));
	handler->data_length = 0;
	debug_log = &handler->log.base;
}

/**
 * Helper function to release the crash dump looging and clear the global log.

 * @param test The test framework.
 * @param handler The testing components to release.
 */
static void crash_dump_logging_testing_validate_and_release_dependencies (CuTest *test,
	struct crash_dump_logging_testing *handler)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&handler->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Tear down the test suite.
 *
 * @param test The test framework.
 */
static void crash_dump_logging_testing_suite_tear_down (CuTest *test)
{
	debug_log = NULL;
}

/*******************
 * Test cases
 *******************/

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte (CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data_length = 16;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_wrong_log_entry (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_HEADER,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_HEADER,
		.arg1 = 3,
		.arg2 = 4
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data_length = 16;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	status = logging_mock_validate_and_release (&handler.log);
	CuAssertIntEquals (test, 1, status);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_data_corrupted (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 0x44;
	handler.data_length = 16;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	status = logging_mock_validate_and_release (&handler.log);
	CuAssertIntEquals (test, 1, status);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_1byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x55,
		.arg2 = 0
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;

	handler.data_length = 17;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_2byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x5555,
		.arg2 = 0
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;

	handler.data_length = 18;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_3byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x555555,
		.arg2 = 0
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;

	handler.data_length = 19;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_4byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x55555555,
		.arg2 = 0
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;

	handler.data_length = 20;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_5byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x55555555,
		.arg2 = 0x66
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;
	handler.data[5] = 0x66666666;

	handler.data_length = 21;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_6byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x55555555,
		.arg2 = 0x6666
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;
	handler.data[5] = 0x66666666;

	handler.data_length = 22;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

static void crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_7byte (
	CuTest *test)
{
	int status;
	struct crash_dump_logging_testing handler;
	struct debug_log_entry_info log_entry0 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 1,
		.arg2 = 2
	};
	struct debug_log_entry_info log_entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 3,
		.arg2 = 4
	};

	struct debug_log_entry_info log_entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CRASH_DUMP,
		.msg_index = CRASH_DUMP_LOGGING_OPAQUE_DATA,
		.arg1 = 0x55555555,
		.arg2 = 0x666666
	};

	TEST_START;

	crash_dump_logging_testing_init_dependencies (test, &handler);

	status = mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry0, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry0)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry1)));

	status |= mock_expect (&handler.log.mock, handler.log.base.create_entry, &handler.log, 0,
		MOCK_ARG_PTR_CONTAINS (&log_entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (log_entry2)));

	CuAssertIntEquals (test, 0, status);

	handler.data[0] = 1;
	handler.data[1] = 2;
	handler.data[2] = 3;
	handler.data[3] = 4;
	handler.data[4] = 0x55555555;
	handler.data[5] = 0x66666666;

	handler.data_length = 23;

	crash_dump_logging_save_opaque_data (handler.data, handler.data_length);

	crash_dump_logging_testing_validate_and_release_dependencies (test, &handler);
}

// *INDENT-OFF*
TEST_SUITE_START (crash_dump_logging);

TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_wrong_log_entry);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_data_corrupted);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_1byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_2byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_3byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_4byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_5byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_6byte);
TEST (crash_dump_logging_save_opaque_data_test_length_multiple_8byte_remaining_7byte);

/* Tear down after the tests in this suite have run. */
TEST (crash_dump_logging_testing_suite_tear_down);

TEST_SUITE_END;
// *INDENT-ON*
