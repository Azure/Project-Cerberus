// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ASN1_DICE_ALL_TESTS_H_
#define ASN1_DICE_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'asn1/dice' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_asn1_dice_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_DICE_TCBINFO_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_DICE_TCBINFO_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_dice_tcbinfo);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_DICE_UEID_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_DICE_UEID_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_dice_ueid);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_mbedtls_dice_tcbinfo);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_mbedtls_dice_ueid);
#endif

}


#endif /* ASN1_DICE_ALL_TESTS_H_ */
