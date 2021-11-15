// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_ALL_TESTS_H_
#define MANIFEST_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'manifest' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_manifest_tests (CuSuite *suite)
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
#if (defined TESTING_RUN_MANIFEST_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_FLASH_SUITE
	TESTING_RUN_SUITE (manifest_flash);
	TESTING_RUN_SUITE (manifest_flash_v2);
#endif
#if (defined TESTING_RUN_MANIFEST_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_MANAGER_SUITE
	TESTING_RUN_SUITE (manifest_manager);
#endif
#if (defined TESTING_RUN_MANIFEST_VERIFICATION_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_VERIFICATION_SUITE
	TESTING_RUN_SUITE (manifest_verification);
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


#endif /* MANIFEST_ALL_TESTS_H_ */
