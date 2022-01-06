// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TESTING_H_
#define TESTING_H_

#include <stdint.h>
#include "CuTest/CuTest.h"
#include "platform_io.h"


/**
 * Macro for defining a module test suite to run.
 *
 * @param name The module under test.
 */
#define	TESTING_RUN_SUITE(name) \
	{ \
		CuSuite* get_ ## name ## _suite (void); \
		CuSuiteAddSuite (suite, get_ ## name ## _suite ()); \
	}

/**
 * Create a label for identifying a test suite during execution.
 *
 * @param name The module under test.
 */
#define	TEST_SUITE_LABEL(name)	static const char *SUITE = name;

/**
 * Define a suite of unit tests for a module.  Every TEST_SUITE_START must be followed by a call to
 * TEST_SUITE_END.
 *
 * @param name The module under test.
 */
#define	TEST_SUITE_START(name) \
	CuSuite* get_ ## name ## _suite () \
	{ \
		CuSuite *suite = CuSuiteNew ();

/**
 * Close the definition of a test suite.
 */
#define	TEST_SUITE_END	return suite; }

/**
 * Add a test case to a test suite.  These calls must be between a call to TEST_SUITE_START and one
 * to TEST_SUITE_END.
 *
 * @param func The function that will execute the test case.
 */
#define	TEST(func)	SUITE_ADD_TEST (suite, func)

/**
 * Macro to call at the beginning of every test for easier tracking at run-time.
 */
#define	TEST_START	platform_printf ("%s: %s"NEWLINE, SUITE, __func__)


int testing_validate_array (const uint8_t *expected, const uint8_t *actual, size_t length);
int testing_validate_array_prefix (const uint8_t *expected, const uint8_t *actual, size_t length,
	const char *prefix);
int testing_validate_array_prefix_with_extra_info (const uint8_t *expected, const uint8_t *actual,
	size_t length, const char *prefix, const char *extra);


#endif /* TESTING_H_ */
