// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef COMMON_ALL_TESTS_H_
#define COMMON_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'common' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_common_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_AUTHORIZATION_ALLOWED_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_AUTHORIZATION_ALLOWED_SUITE
	TESTING_RUN_SUITE (authorization_allowed);
#endif
#if (defined TESTING_RUN_AUTHORIZATION_CHALLENGE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_AUTHORIZATION_CHALLENGE_SUITE
	TESTING_RUN_SUITE (authorization_challenge);
#endif
#if (defined TESTING_RUN_AUTHORIZATION_DISALLOWED_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_AUTHORIZATION_DISALLOWED_SUITE
	TESTING_RUN_SUITE (authorization_disallowed);
#endif
#if (defined TESTING_RUN_BUFFER_UTIL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BUFFER_UTIL_SUITE
	TESTING_RUN_SUITE (buffer_util);
#endif
#if (defined TESTING_RUN_IMAGE_HEADER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_IMAGE_HEADER_SUITE
	TESTING_RUN_SUITE (image_header);
#endif
#if (defined TESTING_RUN_OBSERVABLE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_OBSERVABLE_SUITE
	TESTING_RUN_SUITE (observable);
#endif
}


#endif /* COMMON_ALL_TESTS_H_ */
