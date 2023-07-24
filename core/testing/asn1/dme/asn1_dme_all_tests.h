// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ASN1_DME_ALL_TESTS_H_
#define ASN1_DME_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'asn1/dme' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_asn1_dme_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_DME_STRUCTURE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_DME_STRUCTURE_SUITE
	TESTING_RUN_SUITE (dme_structure);
#endif
#if (defined TESTING_RUN_DME_STRUCTURE_RAW_ECC_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_DME_STRUCTURE_RAW_ECC_SUITE
	TESTING_RUN_SUITE (dme_structure_raw_ecc);
#endif
#if (defined TESTING_RUN_DME_STRUCTURE_RAW_ECC_LE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_DME_STRUCTURE_RAW_ECC_LE_SUITE
	TESTING_RUN_SUITE (dme_structure_raw_ecc_le);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_DME_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_DME_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_dme);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_MBEDTLS_DME_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_MBEDTLS_DME_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_mbedtls_dme);
#endif

}


#endif /* ASN1_DME_ALL_TESTS_H_ */
