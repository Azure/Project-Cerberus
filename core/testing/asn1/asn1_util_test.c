// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "asn1/asn1_oid.h"
#include "asn1/asn1_util.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/ecc_testing.h"


TEST_SUITE_LABEL ("asn1_util");


/*******************
 * Test cases
 *******************/

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
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);

	status = asn1_get_der_item_len (buffer_85, sizeof (buffer_85));
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_ECDSA_NO_NULL_SIG_ALGO_DER, 1);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_two_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_CSR_ECC_CA_DER, 2);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_three_byte_length (CuTest *test)
{
	int status;

	TEST_START;

	status = asn1_get_der_item_len (X509_CERTSS_ECC_CA_DER, 3);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_four_byte_length (CuTest *test)
{
	uint8_t buffer_83[] = {0x30, 0x83, 0x10, 0x20, 0x40, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_83, 4);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_get_der_item_len_test_short_buffer_five_byte_length (CuTest *test)
{
	uint8_t buffer_84[] = {0x30, 0x84, 0x10, 0x20, 0x40, 0x50, 0x12, 0x12};
	int status;

	TEST_START;

	status = asn1_get_der_item_len (buffer_84, 5);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
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

static void asn1_encode_integer_test (CuTest *test)
{
	uint64_t value = 127;
	const uint8_t expected[] = {0x02, 0x01, 0x7f};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_zero (CuTest *test)
{
	uint64_t value = 0;
	const uint8_t expected[] = {0x02, 0x01, 0x00};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_multiple_bytes (CuTest *test)
{
	uint64_t value = 256;
	const uint8_t expected[] = {0x02, 0x02, 0x01, 0x00};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_msb_set_add_zero (CuTest *test)
{
	uint64_t value = 128;
	const uint8_t expected[] = {0x02, 0x02, 0x00, 0x80};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_msb_set_not_lsb_add_zero (CuTest *test)
{
	uint64_t value = 0x81234567;
	const uint8_t expected[] = {0x02, 0x05, 0x00, 0x81, 0x23, 0x45, 0x67};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_max_no_padding (CuTest *test)
{
	uint64_t value = 0x1122334400660088;
	const uint8_t expected[] = {0x02, 0x08, 0x11, 0x22, 0x33, 0x44, 0x00, 0x66, 0x00, 0x88};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_max_with_padding (CuTest *test)
{
	uint64_t value = 0xc822004455667700;
	const uint8_t expected[] = {0x02, 0x09, 0x00, 0xc8, 0x22, 0x00, 0x44, 0x55, 0x66, 0x77, 0x00};
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_integer_test_null (CuTest *test)
{
	uint64_t value = 127;
	uint8_t der[3];
	int der_length;

	TEST_START;

	der_length = asn1_encode_integer (value, NULL, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, der_length);
}

static void asn1_encode_integer_test_buffer_less_than_min (CuTest *test)
{
	uint64_t value = 127;
	uint8_t der[3];
	int der_length;

	TEST_START;

	der_length = asn1_encode_integer (value, der, 0);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);

	der_length = asn1_encode_integer (value, der, 1);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);

	der_length = asn1_encode_integer (value, der, 2);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_encode_integer_test_buffer_too_small (CuTest *test)
{
	uint64_t value = 256;
	uint8_t der[3];
	int der_length;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_encode_integer_test_buffer_too_small_not_last_byte (CuTest *test)
{
	uint64_t value = 0x1122334400660088;
	uint8_t der[5];
	int der_length;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_encode_integer_test_buffer_too_small_with_padding (CuTest *test)
{
	uint64_t value = 0xc822004455667700;
	uint8_t der[7];
	int der_length;

	TEST_START;

	der_length = asn1_encode_integer (value, der, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_decode_integer_test (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 127;
	const uint8_t der[] = {0x02, 0x01, 0x7f};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_zero (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 0;
	const uint8_t der[] = {0x02, 0x01, 0x00};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_multiple_bytes (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 256;
	const uint8_t der[] = {0x02, 0x02, 0x01, 0x00};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_msb_set_add_zero (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 128;
	const uint8_t der[] = {0x02, 0x02, 0x00, 0x80};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_msb_set_not_lsb_add_zero (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 0x81234567;
	const uint8_t der[] = {0x02, 0x05, 0x00, 0x81, 0x23, 0x45, 0x67};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_max_no_padding (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 0x1122334400660088;
	const uint8_t der[] = {0x02, 0x08, 0x11, 0x22, 0x33, 0x44, 0x00, 0x66, 0x00, 0x88};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_max_with_padding (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 0xc822004455667700;
	const uint8_t der[] = {0x02, 0x09, 0x00, 0xc8, 0x22, 0x00, 0x44, 0x55, 0x66, 0x77, 0x00};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_extra_bytes (CuTest *test)
{
	uint64_t value;
	uint64_t expected = 256;
	const uint8_t der[] = {0x02, 0x02, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, 0, status);
	CuAssertInt64Equals (test, expected, value);
}

static void asn1_decode_integer_test_null (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x02, 0x01, 0x7f};
	int status;

	TEST_START;

	status = asn1_decode_integer (NULL, sizeof (der), &value);
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, status);

	status = asn1_decode_integer (der, sizeof (der), NULL);
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, status);
}

static void asn1_decode_integer_test_buffer_less_than_min (CuTest *test)
{
	uint64_t value;
	uint8_t der[3];
	int der_length;

	TEST_START;

	der_length = asn1_decode_integer (der, 0, &value);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, der_length);

	der_length = asn1_decode_integer (der, 1, &value);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, der_length);
}

static void asn1_decode_integer_test_buffer_too_small (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x02, 0x01, 0x7f};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der) - 1, &value);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, status);
}

static void asn1_decode_integer_test_value_out_of_range (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x02, 0x09, 0x11, 0x22, 0x33, 0x44, 0x00, 0x66, 0x00, 0x88, 0x99};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, ASN1_UTIL_OUT_OF_RANGE, status);
}

static void asn1_decode_integer_test_value_out_of_range_multiple_bytes (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x02, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x00, 0x66, 0x00, 0x88, 0x99, 0xaa};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, ASN1_UTIL_OUT_OF_RANGE, status);
}

static void asn1_decode_integer_test_negative_value (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x02, 0x01, 0x80};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, ASN1_UTIL_OUT_OF_RANGE, status);
}

static void asn1_decode_integer_test_not_integer_tag (CuTest *test)
{
	uint64_t value;
	const uint8_t der[] = {0x03, 0x01, 0x7f};
	int status;

	TEST_START;

	status = asn1_decode_integer (der, sizeof (der), &value);
	CuAssertIntEquals (test, ASN1_UTIL_UNEXPECTED_TAG, status);
}

static void asn1_encode_base128_oid_test (CuTest *test)
{
	uint8_t expected[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	expected[0] = 0x06;
	expected[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&expected[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_base128_oid_test_longer_value (CuTest *test)
{
	uint8_t expected[X509_EKU_OID_LEN + 2];
	uint8_t der[sizeof (expected)];
	int der_length;
	int status;

	TEST_START;

	expected[0] = 0x06;
	expected[1] = X509_EKU_OID_LEN;
	memcpy (&expected[2], X509_EKU_OID, X509_EKU_OID_LEN);

	der_length = asn1_encode_base128_oid (X509_EKU_OID, X509_EKU_OID_LEN, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), der_length);

	status = testing_validate_array (expected, der, der_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_encode_base128_oid_test_null (CuTest *test)
{
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int der_length;

	TEST_START;

	der_length = asn1_encode_base128_oid (NULL,	ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der,
		sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, der_length);

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256, 0, der, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, der_length);

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, NULL, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, der_length);
}

static void asn1_encode_base128_oid_test_buffer_less_than_min (CuTest *test)
{
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int der_length;

	TEST_START;

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der, 0);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der, 1);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der, 2);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_encode_base128_oid_test_buffer_too_small (CuTest *test)
{
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int der_length;

	TEST_START;

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256,
		ASN1_OID_ECDSA_WITH_SHA256_LENGTH, der, sizeof (der) - 1);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, der_length);
}

static void asn1_encode_base128_oid_test_oid_too_long (CuTest *test)
{
	uint8_t der[128 + 3];
	int der_length;

	TEST_START;

	der_length = asn1_encode_base128_oid (ASN1_OID_ECDSA_WITH_SHA256, 128, der, sizeof (der));
	CuAssertIntEquals (test, ASN1_UTIL_OUT_OF_RANGE, der_length);
}

static void asn1_decode_base128_oid_test (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int status;

	TEST_START;

	der[0] = 0x06;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, oid);
	CuAssertIntEquals (test, ASN1_OID_ECDSA_WITH_SHA256_LENGTH, oid_length);

	status = testing_validate_array (ASN1_OID_ECDSA_WITH_SHA256, oid, oid_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_decode_base128_oid_test_longer_value (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[X509_EKU_OID_LEN + 2];
	int status;

	TEST_START;

	der[0] = 0x06;
	der[1] = X509_EKU_OID_LEN;
	memcpy (&der[2], X509_EKU_OID, X509_EKU_OID_LEN);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, oid);
	CuAssertIntEquals (test, X509_EKU_OID_LEN, oid_length);

	status = testing_validate_array (X509_EKU_OID, oid, oid_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_decode_base128_oid_test_multiple_byte_header (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[128 + 3];
	uint8_t expected[128];
	int status;

	TEST_START;

	memset (der, 1, sizeof (der));
	memset (expected, 1, sizeof (expected));

	der[0] = 0x06;
	der[1] = 0x81;
	der[2] = 128;
	memcpy (&der[3], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);
	memcpy (expected, ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, oid);
	CuAssertIntEquals (test, 128, oid_length);

	status = testing_validate_array (expected, oid, oid_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_decode_base128_oid_test_extra_bytes (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2 + 10];
	int status;

	TEST_START;

	memset (der, 0x55, sizeof (der));

	der[0] = 0x06;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, oid);
	CuAssertIntEquals (test, ASN1_OID_ECDSA_WITH_SHA256_LENGTH, oid_length);

	status = testing_validate_array (ASN1_OID_ECDSA_WITH_SHA256, oid, oid_length);
	CuAssertIntEquals (test, 0, status);
}

static void asn1_decode_base128_oid_test_null (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int status;

	TEST_START;

	der[0] = 0x06;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (NULL, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, status);

	status = asn1_decode_base128_oid (der, sizeof (der), NULL, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, status);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, NULL);
	CuAssertIntEquals (test, ASN1_UTIL_INVALID_ARGUMENT, status);
}

static void asn1_decode_base128_oid_test_buffer_less_than_min (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int status;

	TEST_START;

	der[0] = 0x06;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, 0, &oid, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);

	status = asn1_decode_base128_oid (der, 1, &oid, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_NOT_VALID, status);
}

static void asn1_decode_base128_oid_test_buffer_too_small (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int status;

	TEST_START;

	der[0] = 0x06;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, sizeof (der) - 1, &oid, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_SMALL_DER_BUFFER, status);
}

static void asn1_decode_base128_oid_test_not_object_identifier_tag (CuTest *test)
{
	const uint8_t *oid = NULL;
	size_t oid_length;
	uint8_t der[ASN1_OID_ECDSA_WITH_SHA256_LENGTH + 2];
	int status;

	TEST_START;

	der[0] = 0x05;
	der[1] = ASN1_OID_ECDSA_WITH_SHA256_LENGTH;
	memcpy (&der[2], ASN1_OID_ECDSA_WITH_SHA256, ASN1_OID_ECDSA_WITH_SHA256_LENGTH);

	status = asn1_decode_base128_oid (der, sizeof (der), &oid, &oid_length);
	CuAssertIntEquals (test, ASN1_UTIL_UNEXPECTED_TAG, status);
}


// *INDENT-OFF*
TEST_SUITE_START (asn1_util);

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
TEST (asn1_encode_integer_test);
TEST (asn1_encode_integer_test_zero);
TEST (asn1_encode_integer_test_multiple_bytes);
TEST (asn1_encode_integer_test_msb_set_add_zero);
TEST (asn1_encode_integer_test_msb_set_not_lsb_add_zero);
TEST (asn1_encode_integer_test_max_no_padding);
TEST (asn1_encode_integer_test_max_with_padding);
TEST (asn1_encode_integer_test_null);
TEST (asn1_encode_integer_test_buffer_less_than_min);
TEST (asn1_encode_integer_test_buffer_too_small);
TEST (asn1_encode_integer_test_buffer_too_small_not_last_byte);
TEST (asn1_encode_integer_test_buffer_too_small_with_padding);
TEST (asn1_decode_integer_test);
TEST (asn1_decode_integer_test_zero);
TEST (asn1_decode_integer_test_multiple_bytes);
TEST (asn1_decode_integer_test_msb_set_add_zero);
TEST (asn1_decode_integer_test_msb_set_not_lsb_add_zero);
TEST (asn1_decode_integer_test_max_no_padding);
TEST (asn1_decode_integer_test_max_with_padding);
TEST (asn1_decode_integer_test_extra_bytes);
TEST (asn1_decode_integer_test_null);
TEST (asn1_decode_integer_test_buffer_less_than_min);
TEST (asn1_decode_integer_test_buffer_too_small);
TEST (asn1_decode_integer_test_value_out_of_range);
TEST (asn1_decode_integer_test_value_out_of_range_multiple_bytes);
TEST (asn1_decode_integer_test_negative_value);
TEST (asn1_decode_integer_test_not_integer_tag);
TEST (asn1_encode_base128_oid_test);
TEST (asn1_encode_base128_oid_test_longer_value);
TEST (asn1_encode_base128_oid_test_null);
TEST (asn1_encode_base128_oid_test_buffer_less_than_min);
TEST (asn1_encode_base128_oid_test_buffer_too_small);
TEST (asn1_encode_base128_oid_test_oid_too_long);
TEST (asn1_decode_base128_oid_test);
TEST (asn1_decode_base128_oid_test_longer_value);
TEST (asn1_decode_base128_oid_test_multiple_byte_header);
TEST (asn1_decode_base128_oid_test_extra_bytes);
TEST (asn1_decode_base128_oid_test_null);
TEST (asn1_decode_base128_oid_test_buffer_less_than_min);
TEST (asn1_decode_base128_oid_test_buffer_too_small);
TEST (asn1_decode_base128_oid_test_not_object_identifier_tag);

TEST_SUITE_END;
// *INDENT-ON*
