// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_ALL_TESTS_H_
#define MANIFEST_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "cfm/cfm_all_tests.h"
#include "pcd/pcd_all_tests.h"
#include "pfm/pfm_all_tests.h"


/**
 * Add all tests for components in the 'manifest' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_manifest_tests (CuSuite *suite)
{
#if (defined TESTING_RUN_MANIFEST_CMD_HANDLER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_CMD_HANDLER_SUITE
	TESTING_RUN_SUITE (manifest_cmd_handler);
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
#if (defined TESTING_RUN_MANIFEST_MANAGER_FLASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_MANAGER_FLASH_SUITE
	TESTING_RUN_SUITE (manifest_manager_flash);
#endif
#if (defined TESTING_RUN_MANIFEST_MANAGER_NULL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_MANAGER_NULL_SUITE
	TESTING_RUN_SUITE (manifest_manager_null);
#endif
#if (defined TESTING_RUN_MANIFEST_VERIFICATION_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_MANIFEST_VERIFICATION_SUITE
	TESTING_RUN_SUITE (manifest_verification);
#endif

	add_all_manifest_cfm_tests (suite);
	add_all_manifest_pcd_tests (suite);
	add_all_manifest_pfm_tests (suite);
}


#endif /* MANIFEST_ALL_TESTS_H_ */
