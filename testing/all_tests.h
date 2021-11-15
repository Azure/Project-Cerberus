// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "testing/core_all_tests.h"


/**
 * Add all enabled test suites to the top-level suite that will be executed.
 *
 * @param suite The main test suite.
 */
void add_all_tests (CuSuite *suite)
{
	/* These are all the platform agnostic tests. */
	add_all_core_tests (suite);

	/* These are tests added for specific platforms.  This function must be defined in
	 * 'platform_all_tests.h', which must be available in an include path for the build. */
	add_all_platform_tests (suite);
}


#endif /* ALL_TESTS_H_ */
