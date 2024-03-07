// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_ALL_TESTS_H_
#define TDISP_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'pcisig/tdisp' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_tdisp_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CMD_INTERFACE_TDISP_RESPONDER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_TDISP_RESPONDER_SUITE
	TESTING_RUN_SUITE (cmd_interface_tdisp_responder);
#endif
#if (defined TESTING_RUN_TDISP_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_TDISP_COMMANDS_SUITE
	TESTING_RUN_SUITE (tdisp_commands);
#endif
}


#endif /* TDISP_ALL_TESTS_H_ */

