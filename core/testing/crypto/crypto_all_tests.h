// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CRYPTO_ALL_TESTS_H_
#define CRYPTO_ALL_TESTS_H_

#include "testing.h"
#include "platform_all_tests.h"
#include "kat/crypto_kat_all_tests.h"


/**
 * Add all tests for components in the 'crypto' directory.
 *
 * Be sure to keep the test suites in alphabetical order for easier management.
 *
 * @param suite Suite to add the tests to.
 */
static void add_all_crypto_tests (CuSuite *suite)
{
#if (defined TESTING_RUN_AES_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_AES_MBEDTLS_SUITE
	TESTING_RUN_SUITE (aes_mbedtls);
#endif
#if (defined TESTING_RUN_CHECKSUM_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_CHECKSUM_SUITE
	TESTING_RUN_SUITE (checksum);
#endif
#if (defined TESTING_RUN_ECC_ECC_HW_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECC_ECC_HW_SUITE
	TESTING_RUN_SUITE (ecc_ecc_hw);
#endif
#if (defined TESTING_RUN_ECC_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECC_MBEDTLS_SUITE
	TESTING_RUN_SUITE (ecc_mbedtls);
#endif
#if (defined TESTING_RUN_ECC_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECC_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (ecc_thread_safe);
#endif
#if (defined TESTING_RUN_ECDSA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_ECDSA_SUITE
	TESTING_RUN_SUITE (ecdsa);
#endif
#if (defined TESTING_RUN_HASH_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HASH_SUITE
	TESTING_RUN_SUITE (hash);
#endif
#if (defined TESTING_RUN_HASH_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HASH_MBEDTLS_SUITE
	TESTING_RUN_SUITE (hash_mbedtls);
#endif
#if (defined TESTING_RUN_HASH_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_HASH_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (hash_thread_safe);
#endif
#if (defined TESTING_RUN_KDF_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_KDF_SUITE
	TESTING_RUN_SUITE (kdf);
#endif
#if (defined TESTING_RUN_RNG_DUMMY_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RNG_DUMMY_SUITE
	TESTING_RUN_SUITE (rng_dummy);
#endif
#if (defined TESTING_RUN_RNG_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RNG_MBEDTLS_SUITE
	TESTING_RUN_SUITE (rng_mbedtls);
#endif
#if (defined TESTING_RUN_RNG_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RNG_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (rng_thread_safe);
#endif
#if (defined TESTING_RUN_RSA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RSA_SUITE
	TESTING_RUN_SUITE (rsa);
#endif
#if (defined TESTING_RUN_RSA_MBEDTLS_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RSA_MBEDTLS_SUITE
	TESTING_RUN_SUITE (rsa_mbedtls);
#endif
#if (defined TESTING_RUN_RSA_THREAD_SAFE_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_RSA_THREAD_SAFE_SUITE
	TESTING_RUN_SUITE (rsa_thread_safe);
#endif
#if (defined TESTING_RUN_SIGNATURE_VERIFICATION_ECC_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SIGNATURE_VERIFICATION_ECC_SUITE
	TESTING_RUN_SUITE (signature_verification_ecc);
#endif
#if (defined TESTING_RUN_SIGNATURE_VERIFICATION_RSA_SUITE || \
		defined TESTING_RUN_ALL_TESTS || defined TESTING_RUN_ALL_CORE_TESTS || \
		(!defined TESTING_SKIP_ALL_TESTS && !defined TESTING_SKIP_ALL_CORE_TESTS)) && \
	!defined TESTING_SKIP_SIGNATURE_VERIFICATION_RSA_SUITE
	TESTING_RUN_SUITE (signature_verification_rsa);
#endif

	add_all_crypto_kat_tests (suite);
}


#endif /* CRYPTO_ALL_TESTS_H_ */
