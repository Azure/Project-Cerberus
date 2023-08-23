// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_ALL_TESTS_H_
#define FIRMWARE_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'firmware' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_firmware_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_APP_CONTEXT_NULL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_APP_CONTEXT_NULL_SUITE
	TESTING_RUN_SUITE (app_context_null);
#endif
#if (defined TESTING_RUN_APP_IMAGE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_APP_IMAGE_SUITE
	TESTING_RUN_SUITE (app_image);
#endif
#if (defined TESTING_RUN_FIRMWARE_COMPONENT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_COMPONENT_SUITE
	TESTING_RUN_SUITE (firmware_component);
#endif
#if (defined TESTING_RUN_FIRMWARE_HEADER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_HEADER_SUITE
	TESTING_RUN_SUITE (firmware_header);
#endif
#if (defined TESTING_RUN_FIRMWARE_UPDATE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_UPDATE_SUITE
	TESTING_RUN_SUITE (firmware_update);
#endif
#if (defined TESTING_RUN_FIRMWARE_UPDATE_HANDLER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_UPDATE_HANDLER_SUITE
	TESTING_RUN_SUITE (firmware_update_handler);
#endif
#if (defined TESTING_RUN_FIRMWARE_UPDATE_HANDLER_NO_REVOCATION_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_UPDATE_HANDLER_NO_REVOCATION_SUITE
	TESTING_RUN_SUITE (firmware_update_handler_no_revocation);
#endif
#if (defined TESTING_RUN_FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_SUITE
	TESTING_RUN_SUITE (firmware_update_handler_revoke_after_reset);
#endif
}


#endif /* FIRMWARE_ALL_TESTS_H_ */
