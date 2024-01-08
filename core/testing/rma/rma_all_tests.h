// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RMA_ALL_TESTS_H_
#define RMA_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'rma' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_rma_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CMD_INTERFACE_RMA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CMD_INTERFACE_RMA_SUITE
	TESTING_RUN_SUITE (cmd_interface_rma);
#endif
#if (defined TESTING_RUN_RMA_UNLOCK_TOKEN_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RMA_UNLOCK_TOKEN_SUITE
	TESTING_RUN_SUITE (rma_unlock_token);
#endif
#if (defined TESTING_RUN_SECURE_DEVICE_UNLOCK_RMA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SECURE_DEVICE_UNLOCK_RMA_SUITE
	TESTING_RUN_SUITE (secure_device_unlock_rma);
#endif
}


#endif /* RMA_ALL_TESTS_H_ */
