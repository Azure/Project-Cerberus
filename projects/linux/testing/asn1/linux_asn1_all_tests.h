// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LINUX_ASN1_ALL_TESTS_H_
#define LINUX_ASN1_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'asn1' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_linux_asn1_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_BASE64_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_BASE64_OPENSSL_SUITE
	TESTING_RUN_SUITE (base64_openssl);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_OPENSSL_DICE_TCBINFO_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_OPENSSL_DICE_TCBINFO_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_openssl_dice_tcbinfo);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_openssl_dice_ueid);
#endif
#if (defined TESTING_RUN_X509_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_X509_OPENSSL_SUITE
	TESTING_RUN_SUITE (x509_openssl);
#endif
}


#endif /* LINUX_ASN1_ALL_TESTS_H_ */
