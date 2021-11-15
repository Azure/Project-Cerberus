// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_ALL_TESTS_H_
#define PLATFORM_ALL_TESTS_H_


/* Provide local overrides for any run/skip settings.  This must be included after the platform
 * standard configuration has been applied. */
#if __has_include ("user_all_tests.h")
#include "user_all_tests.h"
#endif


/* This include needs to be after the test execution settings for the settings to apply. */
#include "testing/linux_all_tests.h"

/**
 * Add all tests for common components to be run on Linux.
 *
 * @param suite Suite to add the tests to.
 */
void add_all_platform_tests (CuSuite *suite)
{
	add_all_linux_tests (suite);
}


#endif /* PLATFORM_ALL_TESTS_H_ */
