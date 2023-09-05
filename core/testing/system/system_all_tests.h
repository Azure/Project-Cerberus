// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_ALL_TESTS_H_
#define SYSTEM_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'system' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_system_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_EVENT_TASK_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_EVENT_TASK_SUITE
	TESTING_RUN_SUITE (event_task);
#endif
#if (defined TESTING_RUN_PERIODIC_TASK_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PERIODIC_TASK_SUITE
	TESTING_RUN_SUITE (periodic_task);
#endif
#if (defined TESTING_RUN_SECURITY_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SECURITY_MANAGER_SUITE
	TESTING_RUN_SUITE (security_manager);
#endif
#if (defined TESTING_RUN_SECURITY_MANAGER_NO_UNLOCK_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SECURITY_MANAGER_NO_UNLOCK_SUITE
	TESTING_RUN_SUITE (security_manager_no_unlock);
#endif
#if (defined TESTING_RUN_SECURITY_POLICY_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SECURITY_POLICY_SUITE
	TESTING_RUN_SUITE (security_policy);
#endif
#if (defined TESTING_RUN_SECURITY_POLICY_ENFORCING_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SECURITY_POLICY_ENFORCING_SUITE
	TESTING_RUN_SUITE (security_policy_enforcing);
#endif
#if (defined TESTING_RUN_SYSTEM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SYSTEM_SUITE
	TESTING_RUN_SUITE (system);
#endif
#if (defined TESTING_RUN_SYSTEM_STATE_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SYSTEM_STATE_MANAGER_SUITE
	TESTING_RUN_SUITE (system_state_manager);
#endif
}


#endif /* SYSTEM_ALL_TESTS_H_ */
