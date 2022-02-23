// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_ALL_TESTS_H_
#define MCTP_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'mctp' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_mctp_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CMD_INTERFACE_MCTP_CONTROL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_MCTP_CONTROL_SUITE
	TESTING_RUN_SUITE (cmd_interface_mctp_control);
#endif
#if (defined TESTING_RUN_MCTP_BASE_PROTOCOL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MCTP_BASE_PROTOCOL_SUITE
	TESTING_RUN_SUITE (mctp_base_protocol);
#endif
#if (defined TESTING_RUN_MCTP_CONTROL_PROTOCOL_COMMANDS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MCTP_CONTROL_PROTOCOL_COMMANDS_SUITE
	TESTING_RUN_SUITE (mctp_control_protocol_commands);
#endif
#if (defined TESTING_RUN_MCTP_INTERFACE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MCTP_INTERFACE_SUITE
	TESTING_RUN_SUITE (mctp_interface);
#endif
}


#endif /* MCTP_ALL_TESTS_H_ */
