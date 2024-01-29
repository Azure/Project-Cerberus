// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_ALL_TESTS_H_
#define PCD_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'manifest\pcd' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_manifest_pcd_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_MANIFEST_CMD_HANDLER_PCD_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_CMD_HANDLER_PCD_SUITE
	TESTING_RUN_SUITE (manifest_cmd_handler_pcd);
#endif
#if (defined TESTING_RUN_PCD_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PCD_FLASH_SUITE
	TESTING_RUN_SUITE (pcd_flash);
#endif
#if (defined TESTING_RUN_PCD_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PCD_MANAGER_SUITE
	TESTING_RUN_SUITE (pcd_manager);
#endif
#if (defined TESTING_RUN_PCD_MANAGER_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PCD_MANAGER_FLASH_SUITE
	TESTING_RUN_SUITE (pcd_manager_flash);
#endif
#if (defined TESTING_RUN_PCD_OBSERVER_PCR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PCD_OBSERVER_PCR_SUITE
	TESTING_RUN_SUITE (pcd_observer_pcr);
#endif
}


#endif /* PCD_ALL_TESTS_H_ */
