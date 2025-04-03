// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ACVP_ALL_TESTS_H_
#define ACVP_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'acvp' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_acvp_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_ACVP_PROTO_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ACVP_PROTO_SUITE
	TESTING_RUN_SUITE (acvp_proto);
#endif
#if (defined TESTING_RUN_ACVP_PROTO_TESTER_ADAPTER_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ACVP_PROTO_TESTER_ADAPTER_SUITE
	TESTING_RUN_SUITE (acvp_proto_tester_adapter);
#endif
#if (defined TESTING_RUN_BACKEND_AEAD_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BACKEND_AEAD_SUITE
	TESTING_RUN_SUITE (backend_aead);
#endif
#if (defined TESTING_RUN_BACKEND_SHA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BACKEND_SHA_SUITE
	TESTING_RUN_SUITE (backend_sha);
#endif
}


#endif /* ACVP_ALL_TESTS_H_ */
