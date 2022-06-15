// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "crypto/asn1.h"
#include "testing/crypto/x509_testing.h"


TEST_SUITE_LABEL ("asn1");


static void asn1_get_der_item_len_test (CuTest *test)
{
	uint8_t buffer_83[] = {0x30, 0x83, 0x10, 0x00, 0x00, 0x12, 0x12};
	uint8_t buffer_84[] = {0x30, 0x84, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12};
	uint8_t buffer_invalid[] = {0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12};
	int status;

	TEST_START;

	// Type < 0x80
	status = asn1_get_der_item_len (X509_ECDSA_NO_NULL_SIG_ALGO_DER,
		X509_ECDSA_NO_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_ECDSA_NO_NULL_SIG_ALGO_DER_LEN, status);

	status = asn1_get_der_item_len (X509_ECDSA_WITH_NULL_SIG_ALGO_DER,
		X509_ECDSA_WITH_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_ECDSA_WITH_NULL_SIG_ALGO_DER_LEN, status);

	status = asn1_get_der_item_len (X509_RSA_WITH_NULL_SIG_ALGO_DER,
		X509_RSA_WITH_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_RSA_WITH_NULL_SIG_ALGO_DER_LEN, status);

	// Type 0x81
	status = asn1_get_der_item_len (X509_CSR_ECC_CA_DER, X509_CSR_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CSR_ECC_CA_DER_LEN, status);

	// Type 0x82
	status = asn1_get_der_item_len (X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_ECC_CA_DER_LEN, status);

	status = asn1_get_der_item_len (X509_CERTSS_ECC384_CA_DER, X509_CERTSS_ECC384_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, status);

	status = asn1_get_der_item_len (X509_CERTSS_ECC521_CA_DER, X509_CERTSS_ECC521_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_ECC521_CA_DER_LEN, status);

	status = asn1_get_der_item_len (X509_CERTSS_RSA_CA_DER, X509_CERTSS_RSA_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_RSA_CA_DER_LEN, status);

	status = asn1_get_der_item_len (X509_CERTSS_RSA4K_CA_DER, X509_CERTSS_RSA4K_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_RSA4K_CA_DER_LEN, status);

	// Type 0x83
	status = asn1_get_der_item_len (buffer_83, sizeof (buffer_83));
	CuAssertIntEquals (test, 0x100005, status);

	// Type 0x84
	status = asn1_get_der_item_len (buffer_84, sizeof (buffer_84));
	CuAssertIntEquals (test, 0x1000006, status);

	// Type invalid
	status = asn1_get_der_item_len (buffer_invalid, sizeof (buffer_invalid));
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_buffer_with_multiple_certs (CuTest *test)
{
	uint8_t cert_buffer[X509_CERTSS_ECC_CA_DER_LEN + X509_CERTSS_ECC384_CA_DER_LEN];
	int status;

	memcpy (cert_buffer, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);
	memcpy (cert_buffer + X509_CERTSS_ECC_CA_DER_LEN, X509_CERTSS_ECC384_CA_DER,
		X509_CERTSS_ECC384_CA_DER_LEN);

	TEST_START;

	status = asn1_get_der_item_len (cert_buffer, sizeof (cert_buffer));
	CuAssertIntEquals (test, X509_CERTSS_ECC_CA_DER_LEN, status);

	status = asn1_get_der_item_len (cert_buffer + X509_CERTSS_ECC_CA_DER_LEN,
		sizeof (cert_buffer) - X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CERTSS_ECC384_CA_DER_LEN, status);
}

static void asn1_get_der_item_len_test_invalid_cert (CuTest *test)
{
	uint8_t cert_buffer[X509_CERTSS_ECC_CA_DER_LEN];
	uint8_t buffer_83[] = {0x30, 0x83, 0x10, 0x00, 0x00, 0x12, 0x12};
	uint8_t buffer_84[] = {0x30, 0x84, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12};
	int status;

	TEST_START;

	memset (cert_buffer, 0xAA, sizeof (cert_buffer));

	status = asn1_get_der_item_len (cert_buffer, sizeof (cert_buffer));
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);

	memcpy (cert_buffer, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);

	status = asn1_get_der_item_len (cert_buffer, 2);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);

	status = asn1_get_der_item_len (buffer_83, 4);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);

	status = asn1_get_der_item_len (buffer_84, 5);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_null (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (NULL, 1000);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (asn1);

TEST (asn1_get_der_item_len_test);
TEST (asn1_get_der_item_len_test_buffer_with_multiple_certs);
TEST (asn1_get_der_item_len_test_invalid_cert);
TEST (asn1_get_der_item_len_test_null);

TEST_SUITE_END;
