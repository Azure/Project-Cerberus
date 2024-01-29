// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_ALL_TESTS_H_
#define CFM_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'manifest\cfm' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_manifest_cfm_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_CFM_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CFM_FLASH_SUITE
	TESTING_RUN_SUITE (cfm_flash);
#endif
#if (defined TESTING_RUN_CFM_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CFM_MANAGER_SUITE
	TESTING_RUN_SUITE (cfm_manager);
#endif
#if (defined TESTING_RUN_CFM_MANAGER_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CFM_MANAGER_FLASH_SUITE
	TESTING_RUN_SUITE (cfm_manager_flash);
#endif
#if (defined TESTING_RUN_CFM_OBSERVER_PCR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CFM_OBSERVER_PCR_SUITE
	TESTING_RUN_SUITE (cfm_observer_pcr);
#endif
#if (defined TESTING_RUN_MANIFEST_CMD_HANDLER_CFM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_CMD_HANDLER_CFM_SUITE
	TESTING_RUN_SUITE (manifest_cmd_handler_cfm);
#endif
}


#endif /* CFM_ALL_TESTS_H_ */
