// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_ALL_TESTS_H_
#define RECOVERY_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'recovery' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_recovery_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_OCP_RECOVERY_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_OCP_RECOVERY_SUITE
	TESTING_RUN_SUITE (ocp_recovery);
#endif
#if (defined TESTING_RUN_OCP_RECOVERY_DEVICE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_OCP_RECOVERY_DEVICE_SUITE
	TESTING_RUN_SUITE (ocp_recovery_device);
#endif
#if (defined TESTING_RUN_OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_OCP_RECOVERY_DEVICE_VARIABLE_CMS_LOG_SUITE
	TESTING_RUN_SUITE (ocp_recovery_device_variable_cms_log);
#endif
#if (defined TESTING_RUN_OCP_RECOVERY_SMBUS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_OCP_RECOVERY_SMBUS_SUITE
	TESTING_RUN_SUITE (ocp_recovery_smbus);
#endif
#if (defined TESTING_RUN_RECOVERY_IMAGE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RECOVERY_IMAGE_SUITE
	TESTING_RUN_SUITE (recovery_image);
#endif
#if (defined TESTING_RUN_RECOVERY_IMAGE_HEADER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RECOVERY_IMAGE_HEADER_SUITE
	TESTING_RUN_SUITE (recovery_image_header);
#endif
#if (defined TESTING_RUN_RECOVERY_IMAGE_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RECOVERY_IMAGE_MANAGER_SUITE
	TESTING_RUN_SUITE (recovery_image_manager);
#endif
#if (defined TESTING_RUN_RECOVERY_IMAGE_OBSERVER_PCR_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RECOVERY_IMAGE_OBSERVER_PCR_SUITE
	TESTING_RUN_SUITE (recovery_image_observer_pcr);
#endif
#if (defined TESTING_RUN_RECOVERY_IMAGE_SECTION_HEADER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RECOVERY_IMAGE_SECTION_HEADER_SUITE
	TESTING_RUN_SUITE (recovery_image_section_header);
#endif
}


#endif /* RECOVERY_ALL_TESTS_H_ */
