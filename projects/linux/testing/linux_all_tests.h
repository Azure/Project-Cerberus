// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LINUX_ALL_TESTS_H_
#define LINUX_ALL_TESTS_H_

#include <openssl/evp.h>
#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


TEST_SUITE_LABEL ("linux");


void linux_teardown (CuTest *test)
{
	TEST_START;

	EVP_cleanup ();
}

/**
 * Add all tests for Linux platform components.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
void add_all_linux_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

	OpenSSL_add_all_algorithms ();

#if (defined TESTING_RUN_AES_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_AES_OPENSSL_SUITE
	TESTING_RUN_SUITE (aes_openssl);
#endif
#if (defined TESTING_RUN_BASE64_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_BASE64_OPENSSL_SUITE
	TESTING_RUN_SUITE (base64_openssl);
#endif
#if (defined TESTING_RUN_HASH_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_HASH_OPENSSL_SUITE
	TESTING_RUN_SUITE (hash_openssl);
#endif
#if (defined TESTING_RUN_ECC_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_ECC_OPENSSL_SUITE
	TESTING_RUN_SUITE (ecc_openssl);
#endif
#if (defined TESTING_RUN_RNG_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_RNG_OPENSSL_SUITE
	TESTING_RUN_SUITE (rng_openssl);
#endif
#if (defined TESTING_RUN_RSA_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_RSA_OPENSSL_SUITE
	TESTING_RUN_SUITE (rsa_openssl);
#endif
#if (defined TESTING_RUN_X509_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_X509_OPENSSL_SUITE
	TESTING_RUN_SUITE (x509_openssl);
#endif

	SUITE_ADD_TEST (suite, linux_teardown);
}


#endif /* LINUX_ALL_TESTS_H_ */
