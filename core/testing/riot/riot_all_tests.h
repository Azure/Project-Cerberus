// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RIOT_ALL_TESTS_H_
#define RIOT_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'riot' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_riot_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_BASE64_RIOT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BASE64_RIOT_SUITE
	TESTING_RUN_SUITE (base64_riot);
#endif
#if (defined TESTING_RUN_ECC_RIOT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECC_RIOT_SUITE
	TESTING_RUN_SUITE (ecc_riot);
#endif
#if (defined TESTING_RUN_HASH_RIOT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HASH_RIOT_SUITE
	TESTING_RUN_SUITE (hash_riot);
#endif
#if (defined TESTING_RUN_RIOT_CORE_COMMON_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RIOT_CORE_COMMON_SUITE
	TESTING_RUN_SUITE (riot_core_common);
#endif
#if (defined TESTING_RUN_RIOT_KEY_MANAGER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RIOT_KEY_MANAGER_SUITE
	TESTING_RUN_SUITE (riot_key_manager);
#endif
#if (defined TESTING_RUN_X509_RIOT_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_RIOT_SUITE
	TESTING_RUN_SUITE (x509_riot);
#endif
}


#endif /* RIOT_ALL_TESTS_H_ */
