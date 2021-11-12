// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LINUX_ALL_TESTS_H_
#define LINUX_ALL_TESTS_H_

#include <openssl/evp.h>
#include "CuTest/CuTest.h"
#include "common/unused.h"
#include "testing.h"


const char *SUITE = "linux";


//#define	TESTING_RUN_HASH_OPENSSL_SUITE
//#define	TESTING_RUN_RSA_OPENSSL_SUITE
//#define	TESTING_RUN_ECC_OPENSSL_SUITE
//#define	TESTING_RUN_X509_OPENSSL_SUITE
//#define	TESTING_RUN_AES_OPENSSL_SUITE
//#define	TESTING_RUN_BASE64_OPENSSL_SUITE
//#define	TESTING_RUN_RNG_OPENSSL_SUITE


CuSuite* get_hash_openssl_suite (void);
CuSuite* get_rsa_openssl_suite (void);
CuSuite* get_ecc_openssl_suite (void);
CuSuite* get_x509_openssl_suite (void);
CuSuite* get_aes_openssl_suite (void);
CuSuite* get_base64_openssl_suite (void);
CuSuite* get_rng_openssl_suite (void);

void linux_teardown (CuTest *test)
{
	TEST_START;

	EVP_cleanup ();
}

void add_all_linux_tests (CuSuite *suite)
{
	/* This is unused when no tests will be executed. */
	UNUSED (suite);

	OpenSSL_add_all_algorithms ();

#ifdef TESTING_RUN_HASH_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_hash_openssl_suite ());
#endif
#ifdef TESTING_RUN_RSA_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_rsa_openssl_suite ());
#endif
#ifdef TESTING_RUN_ECC_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_ecc_openssl_suite ());
#endif
#ifdef TESTING_RUN_X509_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_x509_openssl_suite ());
#endif
#ifdef TESTING_RUN_AES_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_aes_openssl_suite ());
#endif
#ifdef TESTING_RUN_BASE64_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_base64_openssl_suite ());
#endif
#ifdef TESTING_RUN_RNG_OPENSSL_SUITE
	CuSuiteAddSuite (suite, get_rng_openssl_suite ());
#endif

	SUITE_ADD_TEST (suite, linux_teardown);
}


#endif /* LINUX_ALL_TESTS_H_ */
