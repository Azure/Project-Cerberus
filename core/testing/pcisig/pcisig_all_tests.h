// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCISIG_ALL_TESTS_H_
#define PCISIG_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"
#include "doe/doe_all_tests.h"
#include "ide/ide_all_tests.h"
#include "tdisp/tdisp_all_tests.h"


/**
 * Add all tests for components in the 'pcisig' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_pcisig_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

	add_all_doe_tests (suite);
	add_all_ide_tests (suite);
	add_all_tdisp_tests (suite);
}


#endif /* PCISIG_ALL_TESTS_H_ */
