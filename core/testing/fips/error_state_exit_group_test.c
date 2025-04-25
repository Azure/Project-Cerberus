// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "common/unused.h"
#include "fips/error_state_exit_group.h"
#include "fips/error_state_exit_group_static.h"
#include "testing/mock/fips/error_state_exit_mock.h"


TEST_SUITE_LABEL ("error_state_exit_group");


/**
 * Dependencies for testing a group of error state exit handlers.
 */
struct error_state_exit_group_testing {
	struct error_state_exit_mock error_state[3];		/**< Mock for error state handling. */
	const struct error_state_exit_interface *list[3];	/**< List of error state handlers. */
	struct error_state_exit_group test;					/**< Group instance under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param group Testing dependencies to initialize.
 */
static void error_state_exit_group_testing_init_dependencies (CuTest *test,
	struct error_state_exit_group_testing *group)
{
	int status;

	status = error_state_exit_mock_init (&group->error_state[0]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&group->error_state[0].mock, "error_state_exit[0]");
	group->list[0] = &group->error_state[0].base;

	status = error_state_exit_mock_init (&group->error_state[1]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&group->error_state[1].mock, "error_state_exit[1]");
	group->list[1] = &group->error_state[1].base;

	status = error_state_exit_mock_init (&group->error_state[2]);
	CuAssertIntEquals (test, 0, status);

	mock_set_name (&group->error_state[2].mock, "error_state_exit[2]");
	group->list[2] = &group->error_state[2].base;
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param group Testing dependencies to release.
 */
static void error_state_exit_group_testing_release_dependencies (CuTest *test,
	struct error_state_exit_group_testing *group)
{
	int status;

	status = error_state_exit_mock_validate_and_release (&group->error_state[0]);
	status |= error_state_exit_mock_validate_and_release (&group->error_state[1]);
	status |= error_state_exit_mock_validate_and_release (&group->error_state[2]);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a group of error state handlers for testing.
 *
 * @param test The test framework.
 * @param group Testing components to initialize.
 * @param count The number of tests to include in the group.
 */
static void error_state_exit_group_testing_init (CuTest *test,
	struct error_state_exit_group_testing *group, size_t count)
{
	int status;

	error_state_exit_group_testing_init_dependencies (test, group);

	status = error_state_exit_group_init (&group->test, group->list, count);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param group Testing components to release.
 */
static void error_state_exit_group_testing_release (CuTest *test,
	struct error_state_exit_group_testing *group)
{
	error_state_exit_group_release (&group->test);
	error_state_exit_group_testing_release_dependencies (test, group);
}


/*******************
 * Test cases
 *******************/

static void error_state_exit_group_test_init (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status;

	TEST_START;

	error_state_exit_group_testing_init_dependencies (test, &group);

	status = error_state_exit_group_init (&group.test, group.list, ARRAY_SIZE (group.list));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, group.test.base.exit_error_state);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_init_null (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status;

	TEST_START;

	error_state_exit_group_testing_init_dependencies (test, &group);

	status = error_state_exit_group_init (NULL, group.list, ARRAY_SIZE (group.list));
	CuAssertIntEquals (test, ERROR_STATE_EXIT_INVALID_ARGUMENT, status);

	status = error_state_exit_group_init (&group.test, NULL, ARRAY_SIZE (group.list));
	CuAssertIntEquals (test, ERROR_STATE_EXIT_INVALID_ARGUMENT, status);

	status = error_state_exit_group_init (&group.test, group.list, 0);
	CuAssertIntEquals (test, ERROR_STATE_EXIT_INVALID_ARGUMENT, status);

	error_state_exit_group_testing_release_dependencies (test, &group);
}

static void error_state_exit_group_test_static_init (CuTest *test)
{
	struct error_state_exit_group_testing group = {
		.test = error_state_exit_group_static_init (group.list, ARRAY_SIZE (group.list))
	};

	TEST_START;

	CuAssertPtrNotNull (test, group.test.base.exit_error_state);

	error_state_exit_group_testing_init_dependencies (test, &group);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_release_null (CuTest *test)
{
	TEST_START;

	error_state_exit_group_release (NULL);
}

static void error_state_exit_group_test_exit_error_state_single_handler (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status;

	TEST_START;

	error_state_exit_group_testing_init (test, &group, 1);

	status = mock_expect (&group.error_state[0].mock, group.error_state[0].base.exit_error_state,
		&group.error_state[0], 0);
	CuAssertIntEquals (test, 0, status);

	status = group.test.base.exit_error_state (&group.test.base);
	CuAssertIntEquals (test, 0, status);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_exit_error_state_multiple_handlers (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status = 0;
	size_t i;

	TEST_START;

	error_state_exit_group_testing_init (test, &group, ARRAY_SIZE (group.list));

	for (i = 0; i < ARRAY_SIZE (group.list); i++) {
		status |= mock_expect (&group.error_state[i].mock,
			group.error_state[i].base.exit_error_state, &group.error_state[i], 0);
	}

	CuAssertIntEquals (test, 0, status);

	status = group.test.base.exit_error_state (&group.test.base);
	CuAssertIntEquals (test, 0, status);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_exit_error_state_static_init (CuTest *test)
{
	struct error_state_exit_group_testing group = {
		.test = error_state_exit_group_static_init (group.list, ARRAY_SIZE (group.list))
	};
	int status = 0;
	size_t i;

	TEST_START;

	error_state_exit_group_testing_init_dependencies (test, &group);

	for (i = 0; i < ARRAY_SIZE (group.list); i++) {
		status |= mock_expect (&group.error_state[i].mock,
			group.error_state[i].base.exit_error_state, &group.error_state[i], 0);
	}

	CuAssertIntEquals (test, 0, status);

	status = group.test.base.exit_error_state (&group.test.base);
	CuAssertIntEquals (test, 0, status);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_exit_error_state_null (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status;

	TEST_START;

	error_state_exit_group_testing_init (test, &group, 1);

	status = group.test.base.exit_error_state (NULL);
	CuAssertIntEquals (test, ERROR_STATE_EXIT_INVALID_ARGUMENT, status);

	error_state_exit_group_testing_release (test, &group);
}

static void error_state_exit_group_test_exit_error_state_failure (CuTest *test)
{
	struct error_state_exit_group_testing group;
	int status;

	TEST_START;

	error_state_exit_group_testing_init (test, &group, ARRAY_SIZE (group.list));

	status = mock_expect (&group.error_state[0].mock, group.error_state[0].base.exit_error_state,
		&group.error_state[0], 0);
	status = mock_expect (&group.error_state[1].mock, group.error_state[1].base.exit_error_state,
		&group.error_state[1], ERROR_STATE_EXIT_EXIT_FAILED);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, status);

	status = group.test.base.exit_error_state (&group.test.base);
	CuAssertIntEquals (test, ERROR_STATE_EXIT_EXIT_FAILED, status);

	error_state_exit_group_testing_release (test, &group);
}


// *INDENT-OFF*
TEST_SUITE_START (error_state_exit_group);

TEST (error_state_exit_group_test_init);
TEST (error_state_exit_group_test_init_null);
TEST (error_state_exit_group_test_static_init);
TEST (error_state_exit_group_test_release_null);
TEST (error_state_exit_group_test_exit_error_state_single_handler);
TEST (error_state_exit_group_test_exit_error_state_multiple_handlers);
TEST (error_state_exit_group_test_exit_error_state_static_init);
TEST (error_state_exit_group_test_exit_error_state_null);
TEST (error_state_exit_group_test_exit_error_state_failure);

TEST_SUITE_END;
// *INDENT-ON*
