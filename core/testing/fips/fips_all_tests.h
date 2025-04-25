// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIPS_ALL_TESTS_H_
#define FIPS_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'fips' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_fips_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CMD_CHANNEL_ERROR_STATE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_CHANNEL_ERROR_STATE_SUITE
	TESTING_RUN_SUITE (cmd_channel_error_state);
#endif
#if (defined TESTING_RUN_CMD_CHANNEL_ERROR_STATE_WITH_EXIT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_CHANNEL_ERROR_STATE_WITH_EXIT_SUITE
	TESTING_RUN_SUITE (cmd_channel_error_state_with_exit);
#endif
#if (defined TESTING_RUN_ERROR_STATE_ENTRY_GROUP_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ERROR_STATE_ENTRY_GROUP_SUITE
	TESTING_RUN_SUITE (error_state_entry_group);
#endif
#if (defined TESTING_RUN_ERROR_STATE_EXIT_GROUP_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ERROR_STATE_EXIT_GROUP_SUITE
	TESTING_RUN_SUITE (error_state_exit_group);
#endif
#if (defined TESTING_RUN_PERIODIC_SELF_TEST_HANDLER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PERIODIC_SELF_TEST_HANDLER_SUITE
	TESTING_RUN_SUITE (periodic_self_test_handler);
#endif
}


#endif /* FIPS_ALL_TESTS_H_ */
