// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/x509.h"
#include "spdm/cert_chain_verifier_interface.h"


TEST_SUITE_LABEL ("cert_chain_verifier_interface");


/*******************
 * Test cases
 *******************/

static void cert_chain_verifier_interface_test_result_release_null (CuTest *test)
{
	TEST_START;

	/* Releasing a null result must be a safe no-op. */
	cert_chain_verifier_result_release (NULL);
}

static void cert_chain_verifier_interface_test_result_release (CuTest *test)
{
	struct cert_chain_verifier_result result;
	uint8_t *alias_key;
	uint8_t *root_cert;

	TEST_START;

	alias_key = platform_malloc (4);
	CuAssertPtrNotNull (test, alias_key);
	root_cert = platform_malloc (8);
	CuAssertPtrNotNull (test, root_cert);

	result.key_type = X509_PUBLIC_KEY_ECC;
	result.alias_key = alias_key;
	result.alias_key_length = 4;
	result.root_cert.cert = root_cert;
	result.root_cert.length = 8;

	cert_chain_verifier_result_release (&result);

	CuAssertIntEquals (test, 0, result.key_type);
	CuAssertPtrEquals (test, NULL, (void*) result.alias_key);
	CuAssertIntEquals (test, 0, result.alias_key_length);
	CuAssertPtrEquals (test, NULL, (void*) result.root_cert.cert);
	CuAssertIntEquals (test, 0, result.root_cert.length);
}

static void cert_chain_verifier_interface_test_result_release_already_cleared (CuTest *test)
{
	struct cert_chain_verifier_result result;

	TEST_START;

	memset (&result, 0, sizeof (result));

	/* Releasing a zeroed result is safe and leaves it zeroed (double-release safe). */
	cert_chain_verifier_result_release (&result);

	CuAssertIntEquals (test, 0, result.key_type);
	CuAssertPtrEquals (test, NULL, (void*) result.alias_key);
	CuAssertIntEquals (test, 0, result.alias_key_length);
	CuAssertPtrEquals (test, NULL, (void*) result.root_cert.cert);
	CuAssertIntEquals (test, 0, result.root_cert.length);
}


// *INDENT-OFF*
TEST_SUITE_START (cert_chain_verifier_interface);

TEST (cert_chain_verifier_interface_test_result_release_null);
TEST (cert_chain_verifier_interface_test_result_release);
TEST (cert_chain_verifier_interface_test_result_release_already_cleared);

TEST_SUITE_END;
// *INDENT-ON*
