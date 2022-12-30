// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "crypto/asn1.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/x509_testing.h"


TEST_SUITE_LABEL ("asn1");


static void asn1_get_der_item_len_test_single_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_ECDSA_NO_NULL_SIG_ALGO_DER,
		X509_ECDSA_NO_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_ECDSA_NO_NULL_SIG_ALGO_DER_LEN, status);

	status = asn1_get_der_item_len (X509_ECDSA_WITH_NULL_SIG_ALGO_DER,
		X509_ECDSA_WITH_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_ECDSA_WITH_NULL_SIG_ALGO_DER_LEN, status);

	status = asn1_get_der_item_len (X509_RSA_WITH_NULL_SIG_ALGO_DER,
		X509_RSA_WITH_NULL_SIG_ALGO_DER_LEN);
	CuAssertIntEquals (test, X509_RSA_WITH_NULL_SIG_ALGO_DER_LEN, status);
}

static void asn1_get_der_item_len_test_two_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_CSR_ECC_CA_DER, X509_CSR_ECC_CA_DER_LEN);
	CuAssertIntEquals (test, X509_CSR_ECC_CA_DER_LEN, status);
}

static void asn1_get_der_item_len_test_three_byte_length (CuTest *test)
{
	int status;

	TEST_START;

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
}

static void asn1_get_der_item_len_test_four_byte_length (CuTest *test)
{
	uint8_t buffer_83[] = {0x30, 0x83, 0x10, 0x20, 0x40, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_83, sizeof (buffer_83));
	CuAssertIntEquals (test, 0x102045, status);
}

static void asn1_get_der_item_len_test_five_byte_length (CuTest *test)
{
	uint8_t buffer_84[] = {0x30, 0x84, 0x10, 0x20, 0x40, 0x50, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_84, sizeof (buffer_84));
	CuAssertIntEquals (test, 0x10204056, status);
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

static void asn1_get_der_item_len_test_null (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (NULL, 1000);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_get_der_item_len_test_invalid_length_identifier (CuTest *test)
{
	uint8_t buffer_80[] = {0x30, 0x80, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12};
	uint8_t buffer_85[] = {0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_80, sizeof (buffer_85));
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);

	status = asn1_get_der_item_len (buffer_85, sizeof (buffer_85));
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_ECDSA_NO_NULL_SIG_ALGO_DER, 1);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_two_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_CSR_ECC_CA_DER, 2);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_three_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_CERTSS_ECC_CA_DER, 3);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_four_byte_length (CuTest *test)
{
	uint8_t buffer_83[] = {0x30, 0x83, 0x10, 0x20, 0x40, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_83, 4);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_five_byte_length (CuTest *test)
{
	uint8_t buffer_84[] = {0x30, 0x84, 0x10, 0x20, 0x40, 0x50, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_84, 5);
	CuAssertIntEquals (test, ASN1_NOT_VALID, status);
}

static void asn1_get_der_encoded_length_test (CuTest *test)
{
	size_t length;

	TEST_START;

	length = asn1_get_der_encoded_length (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, (int) length);
}

static void asn1_get_der_encoded_length_test_extra_length (CuTest *test)
{
	uint8_t der_padded[ECC_PUBKEY_DER_LEN + 10];
	size_t length;

	TEST_START;

	memcpy (der_padded, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	length = asn1_get_der_encoded_length (der_padded, sizeof (der_padded));
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, (int) length);
}

static void asn1_get_der_encoded_length_test_short_buffer (CuTest *test)
{
	size_t length;
	size_t der_length = ECC384_PUBKEY_DER_LEN - 10;

	TEST_START;

	length = asn1_get_der_encoded_length (ECC384_PUBKEY_DER, der_length);
	CuAssertIntEquals (test, der_length, (int) length);
}

static void asn1_get_der_encoded_length_test_invalid_asn1 (CuTest *test)
{
	size_t length;
	size_t der_length = 1;

	TEST_START;

	length = asn1_get_der_encoded_length (ECC384_PUBKEY_DER, der_length);
	CuAssertIntEquals (test, der_length, (int) length);
}

static void asn1_get_der_encoded_length_test_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = asn1_get_der_encoded_length (NULL, 100);
	CuAssertIntEquals (test, 0, (int) length);
}


TEST_SUITE_START (asn1);

TEST (asn1_get_der_item_len_test_single_byte_length);
TEST (asn1_get_der_item_len_test_two_byte_length);
TEST (asn1_get_der_item_len_test_three_byte_length);
TEST (asn1_get_der_item_len_test_four_byte_length);
TEST (asn1_get_der_item_len_test_five_byte_length);
TEST (asn1_get_der_item_len_test_buffer_with_multiple_certs);
TEST (asn1_get_der_item_len_test_null);
TEST (asn1_get_der_item_len_test_invalid_length_identifier);
TEST (asn1_get_der_item_len_test_short_buffer);
TEST (asn1_get_der_item_len_test_short_buffer_two_byte_length);
TEST (asn1_get_der_item_len_test_short_buffer_three_byte_length);
TEST (asn1_get_der_item_len_test_short_buffer_four_byte_length);
TEST (asn1_get_der_item_len_test_short_buffer_five_byte_length);
TEST (asn1_get_der_encoded_length_test);
TEST (asn1_get_der_encoded_length_test_extra_length);
TEST (asn1_get_der_encoded_length_test_short_buffer);
TEST (asn1_get_der_encoded_length_test_invalid_asn1);
TEST (asn1_get_der_encoded_length_test_null);

TEST_SUITE_END;
