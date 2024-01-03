// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LINUX_ALL_TESTS_H_
#define LINUX_ALL_TESTS_H_

#include <openssl/evp.h>
#include "testing.h"
#include "platform_all_tests.h"
#include "asn1/linux_asn1_all_tests.h"
#include "crypto/linux_crypto_all_tests.h"
#include "system/linux_system_all_tests.h"


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
	OpenSSL_add_all_algorithms ();

	add_all_linux_asn1_tests (suite);
	add_all_linux_crypto_tests (suite);
	add_all_linux_system_tests (suite);

	SUITE_ADD_TEST (suite, linux_teardown);
}


#endif /* LINUX_ALL_TESTS_H_ */
