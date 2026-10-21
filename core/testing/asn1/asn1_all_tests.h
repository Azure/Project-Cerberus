// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ASN1_ALL_TESTS_H_
#define ASN1_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "dice/asn1_dice_all_tests.h"
#include "dme/asn1_dme_all_tests.h"


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
	add_all_asn1_dme_tests (suite);

#if (defined TESTING_RUN_ASN1_UTIL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ASN1_UTIL_SUITE
	TESTING_RUN_SUITE (asn1_util);
#endif
#if (defined TESTING_RUN_BASE64_CORE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BASE64_CORE_SUITE
	TESTING_RUN_SUITE (base64_core);
#endif
#if (defined TESTING_RUN_BASE64_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BASE64_MBEDTLS_SUITE
	TESTING_RUN_SUITE (base64_mbedtls);
#endif
#if (defined TESTING_RUN_BASE64_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_BASE64_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (base64_thread_safe);
#endif
#if (defined TESTING_RUN_ECC_DER_UTIL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECC_DER_UTIL_SUITE
	TESTING_RUN_SUITE (ecc_der_util);
#endif
#if (defined TESTING_RUN_X509_CERT_BUILD_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_CERT_BUILD_SUITE
	TESTING_RUN_SUITE (x509_cert_build);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_EKU_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_EKU_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_eku);
#endif
#if (defined TESTING_RUN_X509_EXTENSION_BUILDER_MBEDTLS_EKU_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_EXTENSION_BUILDER_MBEDTLS_EKU_SUITE
	TESTING_RUN_SUITE (x509_extension_builder_mbedtls_eku);
#endif
#if (defined TESTING_RUN_X509_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_MBEDTLS_SUITE
	TESTING_RUN_SUITE (x509_mbedtls);
#endif
#if (defined TESTING_RUN_X509_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_X509_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (x509_thread_safe);
#endif
}


#endif /* ASN1_ALL_TESTS_H_ */
