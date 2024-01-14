// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_ALL_TESTS_H_
#define SPDM_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'spdm' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_spdm_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CMD_INTERFACE_SPDM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_SPDM_SUITE
	TESTING_RUN_SUITE (cmd_interface_spdm);
#endif
#if (defined TESTING_RUN_SPDM_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPDM_COMMANDS_SUITE
	TESTING_RUN_SUITE (spdm_commands);
#endif
#if (defined TESTING_RUN_SPDM_TRANSCRIPT_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SPDM_TRANSCRIPT_MANAGER_SUITE
	TESTING_RUN_SUITE (spdm_transcript_manager);
#endif
}


#endif /* SPDM_ALL_TESTS_H_ */
