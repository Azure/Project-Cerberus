// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ASN1_ALL_TESTS_H_
#define ASN1_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "dice/asn1_dice_all_tests.h"


/**
 * Add all tests for components in the 'asn1' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_asn1_tests (CuSuite *suite)
{
	add_all_asn1_dice_tests (suite);
}


#endif /* ASN1_ALL_TESTS_H_ */
