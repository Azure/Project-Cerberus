// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LINUX_CRYPTO_ALL_TESTS_H_
#define LINUX_CRYPTO_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "common/unused.h"


/**
 * Add all tests for components in the 'crypto' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_linux_crypto_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

#if (defined TESTING_RUN_AES_GCM_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_AES_GCM_OPENSSL_SUITE
	TESTING_RUN_SUITE (aes_gcm_openssl);
#endif
#if (defined TESTING_RUN_AES_XTS_OPENSSL_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_LINUX_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_LINUX_TESTS)) && \
	!defined TESTING_SKIP_AES_XTS_OPENSSL_SUITE
	TESTING_RUN_SUITE (aes_xts_openssl);
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
}


#endif /* LINUX_CRYPTO_ALL_TESTS_H_ */
