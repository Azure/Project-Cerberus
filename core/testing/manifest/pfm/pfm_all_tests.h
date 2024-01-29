// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_ALL_TESTS_H_
#define PFM_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'manifest\pfm' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_manifest_pfm_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_MANIFEST_CMD_HANDLER_PFM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_CMD_HANDLER_PFM_SUITE
	TESTING_RUN_SUITE (manifest_cmd_handler_pfm);
#endif
#if (defined TESTING_RUN_PFM_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PFM_FLASH_SUITE
	TESTING_RUN_SUITE (pfm_flash);
	TESTING_RUN_SUITE (pfm_flash_v2);
#endif
#if (defined TESTING_RUN_PFM_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PFM_MANAGER_SUITE
	TESTING_RUN_SUITE (pfm_manager);
#endif
#if (defined TESTING_RUN_PFM_MANAGER_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PFM_MANAGER_FLASH_SUITE
	TESTING_RUN_SUITE (pfm_manager_flash);
#endif
#if (defined TESTING_RUN_PFM_OBSERVER_PCR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PFM_OBSERVER_PCR_SUITE
	TESTING_RUN_SUITE (pfm_observer_pcr);
#endif
#if (defined TESTING_RUN_PFM_OBSERVER_PENDING_RESET_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_PFM_OBSERVER_PENDING_RESET_SUITE
	TESTING_RUN_SUITE (pfm_observer_pending_reset);
#endif
}


#endif /* PFM_ALL_TESTS_H_ */
