// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/ecc_der_util.h"
#include "crypto/ecc.h"
#include "testing/crypto/ecc_testing.h"


TEST_SUITE_LABEL ("ecc_der_util");


/**
 * A minimum length ASN.1 encoded ECDSA signature.
 */
static const uint8_t ECC_DER_TESTING_MIN_ECDSA[] = {
	0x30,0x06,
	0x02,0x01,0x01,		// An INTEGER with value 1.
	0x02,0x01,0x02		// An INTEGER with value 2.
};

/**
 * The r value for the minimum ECDSA signature with a 256-bit key.
 */
static const uint8_t ECC_DER_TESTING_MIN_ECDSA_R[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

/**
 * The s value for the minimum ECDSA signature with a 256-bit key.
 */
static const uint8_t ECC_DER_TESTING_MIN_ECDSA_S[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};

/**
 * The r value for the minimum ECDSA signature with a 384-bit key.
 */
static const uint8_t ECC384_DER_TESTING_MIN_ECDSA_R[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
};

/**
 * The s value for the minimum ECDSA signature with a 384-bit key.
 */
static const uint8_t ECC384_DER_TESTING_MIN_ECDSA_S[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
};

/**
 * The r value for the minimum ECDSA signature with a 521-bit key.
 */
static const uint8_t ECC521_DER_TESTING_MIN_ECDSA_R[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x01
};

/**
 * The s value for the minimum ECDSA signature with a 521-bit key.
 */
static const uint8_t ECC521_DER_TESTING_MIN_ECDSA_S[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x02
};


/*******************
 * Test cases
 *******************/

static void ecc_der_decode_private_key_test_p256 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY, priv_key, ECC_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_private_key_test_p256_no_pubkey (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC_PRIVKEY_NO_PUBKEY_DER, ECC_PRIVKEY_NO_PUBKEY_DER_LEN,
		priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY, priv_key, ECC_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_private_key_test_p384 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY, priv_key, ECC384_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_private_key_test_p384_no_pubkey (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC384_PRIVKEY_NO_PUBKEY_DER,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, priv_key, sizeof (priv_key));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC384_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY, priv_key, ECC384_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_private_key_test_p521 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY, priv_key, ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_private_key_test_p521_no_leading_zero (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC521_PRIVKEY_DER_NO_LEADING_ZERO,
		ECC521_PRIVKEY_DER_NO_LEADING_ZERO_LEN, priv_key, sizeof (priv_key));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY, priv_key, ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_private_key_test_p521_no_pubkey (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC521_PRIVKEY_NO_PUBKEY_DER,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, priv_key, sizeof (priv_key));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PRIVKEY_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY, priv_key, ECC521_PRIVKEY_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_private_key_test_null (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (NULL, ECC_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_decode_private_key (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_decode_private_key_test_malformed_zero_data (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC_PRIVKEY_DER, 0, priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_sequence_header_short (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC_PRIVKEY_DER, 1, priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_unknown_sequence_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC384_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC384_PRIVKEY_DER, sizeof (der));
	/* Change the length indicator of the SEQUENCE to indicate two length bytes (0x81 -> 0x82). */
	der[1] = 0x82;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNKNOWN_SEQUENCE, status);
}

static void ecc_der_decode_private_key_test_malformed_not_sequence (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the type indicator at the beginning of the buffer. */
	der[0] = 0x03;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_sequence_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the SEQUENCE length to exceed the buffer size. */
	der[1] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_not_integer (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the type indicator for the version INTEGER. */
	der[2] = 0x03;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_integer_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the INTEGER length to exceed the buffer size. */
	der[3] = (sizeof (der) - 2 - 2) + 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_unknown_sequence_version_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the INTEGER length to be more than one byte. */
	der[3] = 2;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNKNOWN_SEQUENCE, status);
}

static void ecc_der_decode_private_key_test_unknown_sequence_not_version_1 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the version value. */
	der[4] = 2;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNKNOWN_SEQUENCE, status);
}

static void ecc_der_decode_private_key_test_malformed_not_octet_string (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the type indicator for the private key OCTET STRING. */
	der[5] = 0x03;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_octet_string_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OCTET STRING length to exceed the buffer size. */
	der[6] = (sizeof (der) - 2 - 2 - 1 - 2) + 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_unsupported_key_length (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OCTET STRING length to an unsupported length. */
	der[6] = (192 / 8);

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
}

static void ecc_der_decode_private_key_test_malformed_not_explicit_parameters (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the type indicator for the EXPLICIT ECDomainParameters. */
	der[39] = 0x03;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_explicit_parameters_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OCTET STRING length to exceed the buffer size. */
	der[40] = (sizeof (der) - 2 - 2 - 1 - 2 - 32 - 2) + 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_not_oid (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the type indicator for the OBJECT IDENTIFIER SECGCurveNames. */
	der[41] = 0x03;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_malformed_oid_too_long (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER length to exceed the buffer size. */
	der[42] = (sizeof (der) - 2 - 2 - 1 - 2 - 32 - 2 - 2) + 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p256 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER length to an unexpected size. */
	der[42] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p256 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER to an unexpected value. */
	der[43] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_small_key_buffer_p256 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_256 - 1];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p384 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_384];
	int status;
	uint8_t der[ECC384_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC384_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER length to an unexpected size. */
	der[59] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p384 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_384];
	int status;
	uint8_t der[ECC384_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC384_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER to an unexpected value. */
	der[62] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_small_key_buffer_p384 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_384 - 1];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p521 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521];
	int status;
	uint8_t der[ECC521_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC521_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER length to an unexpected size. */
	der[77] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p521 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521];
	int status;
	uint8_t der[ECC521_PRIVKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC521_PRIVKEY_DER, sizeof (der));
	/* Change the OBJECT IDENTIFIER to an unexpected value. */
	der[82] += 1;

	status = ecc_der_decode_private_key (der, sizeof (der), priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_private_key_test_small_key_buffer_p521 (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521 - 1];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN, priv_key,
		sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}

static void ecc_der_decode_private_key_test_small_key_buffer_p521_no_leading_zero (CuTest *test)
{
	uint8_t priv_key[ECC_KEY_LENGTH_521 - 1];
	int status;

	TEST_START;

	status = ecc_der_decode_private_key (ECC521_PRIVKEY_DER_NO_LEADING_ZERO,
		ECC521_PRIVKEY_DER_NO_LEADING_ZERO_LEN, priv_key, sizeof (priv_key));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}
#endif

static void ecc_der_encode_private_key_test_p256 (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, ECC_DER_P256_PRIVATE_LENGTH);

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_private_key_test_p256_no_pubkey (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC_PRIVKEY_NO_PUBKEY_DER_LEN, ECC_DER_P256_PRIVATE_NO_PUB_LENGTH);

	status = ecc_der_encode_private_key (ECC_PRIVKEY, NULL, NULL, ECC_KEY_LENGTH_256, der,
		sizeof (der));
	CuAssertIntEquals (test, ECC_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY_NO_PUBKEY_DER, der, ECC_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC_PRIVKEY, NULL, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY_NO_PUBKEY_DER, der, ECC_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, NULL, ECC_KEY_LENGTH_256, der,
		sizeof (der));
	CuAssertIntEquals (test, ECC_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC_PRIVKEY_NO_PUBKEY_DER, der, ECC_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_private_key_test_p384 (CuTest *test)
{
	uint8_t der[ECC_DER_P384_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC384_PRIVKEY_DER_LEN, ECC_DER_P384_PRIVATE_LENGTH);

	status = ecc_der_encode_private_key (ECC384_PRIVKEY, ECC384_PUBKEY,
		&ECC384_PUBKEY[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384, der, sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC384_PRIVKEY_DER_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY_DER, der, ECC384_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_private_key_test_p384_no_pubkey (CuTest *test)
{
	uint8_t der[ECC_DER_P384_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, ECC_DER_P384_PRIVATE_NO_PUB_LENGTH);

	status = ecc_der_encode_private_key (ECC384_PRIVKEY, NULL, NULL, ECC_KEY_LENGTH_384, der,
		sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY_NO_PUBKEY_DER, der,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC384_PRIVKEY, NULL, &ECC384_PUBKEY[ECC_KEY_LENGTH_384],
		ECC_KEY_LENGTH_384, der, sizeof (der));
	CuAssertIntEquals (test, ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY_NO_PUBKEY_DER, der,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC384_PRIVKEY, ECC384_PUBKEY, NULL, ECC_KEY_LENGTH_384,
		der, sizeof (der));
	CuAssertIntEquals (test, ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC384_PRIVKEY_NO_PUBKEY_DER, der,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_private_key_test_p521 (CuTest *test)
{
	uint8_t der[ECC_DER_P521_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC521_PRIVKEY_DER_LEN, ECC_DER_P521_PRIVATE_LENGTH);

	status = ecc_der_encode_private_key (ECC521_PRIVKEY, ECC521_PUBKEY,
		&ECC521_PUBKEY[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521, der, sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PRIVKEY_DER_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY_DER, der, ECC521_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_private_key_test_p521_no_pubkey (CuTest *test)
{
	uint8_t der[ECC_DER_P521_PRIVATE_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, ECC_DER_P521_PRIVATE_NO_PUB_LENGTH);

	status = ecc_der_encode_private_key (ECC521_PRIVKEY, NULL, NULL, ECC_KEY_LENGTH_521, der,
		sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY_NO_PUBKEY_DER, der,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC521_PRIVKEY, NULL, &ECC521_PUBKEY[ECC_KEY_LENGTH_521],
		ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY_NO_PUBKEY_DER, der,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = ecc_der_encode_private_key (ECC521_PRIVKEY, ECC521_PUBKEY, NULL, ECC_KEY_LENGTH_521,
		der, sizeof (der));
	CuAssertIntEquals (test, ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC521_PRIVKEY_NO_PUBKEY_DER, der,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_private_key_test_null (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PRIVATE_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (NULL, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, NULL, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_encode_private_key_test_unsupported_key_length (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PRIVATE_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		(192 / 8), der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
}

static void ecc_der_encode_private_key_test_small_buffer_sequence_p256 (CuTest *test)
{
	uint8_t der[1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_der_encode_private_key_test_small_buffer_sequence_p384 (CuTest *test)
{
	uint8_t der[2];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_encode_private_key_test_small_buffer_sequence_p521 (CuTest *test)
{
	uint8_t der[2];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}
#endif

static void ecc_der_encode_private_key_test_small_buffer_version (CuTest *test)
{
	uint8_t der[2 + 2];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_priv_key (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_explicit_oid (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_oid (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 2 + 2 + 7];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_explicit_pub_key (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 2 + 2 + 8 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_encode_private_key_test_small_buffer_explicit_pub_key_p521 (CuTest *test)
{
	uint8_t der[3 + 2 + 1 + 2 + ECC_KEY_LENGTH_521 + 2 + 2 + 5 + 2];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC521_PRIVKEY, ECC521_PUBKEY,
		&ECC_PUBKEY[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}
#endif

static void ecc_der_encode_private_key_test_small_buffer_bit_string_tag (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 2 + 2 + 8 + 2 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_bit_string_no_space (CuTest *test)
{
	/* Need an extra byte due to the way length checks are implemented. */
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 2 + 2 + 8 + 2 + 2 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_private_key_test_small_buffer_bit_string_short_space (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + 2 + ECC_KEY_LENGTH_256 + 2 + 2 + 8 + 2 + 2 + 2 + ECC_PUBKEY_LEN - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_private_key (ECC_PRIVKEY, ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_decode_public_key_test_p256 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	status = testing_validate_array (ECC_PUBKEY, pub_key_x, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC_PUBKEY[ECC_KEY_LENGTH_256], pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_public_key_test_p384 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_384];
	uint8_t pub_key_y[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN, pub_key_x,
		pub_key_y, ECC_KEY_LENGTH_384);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC_KEY_LENGTH_384, status);

	status = testing_validate_array (ECC384_PUBKEY, pub_key_x, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC384_PUBKEY[ECC_KEY_LENGTH_384], pub_key_y,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_public_key_test_p521 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_521];
	uint8_t pub_key_y[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN, pub_key_x,
		pub_key_y, ECC_KEY_LENGTH_521);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC_KEY_LENGTH_521, status);

	status = testing_validate_array (ECC521_PUBKEY, pub_key_x, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC521_PUBKEY[ECC_KEY_LENGTH_521], pub_key_y,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_decode_public_key_test_null (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (NULL, ECC_PUBKEY_DER_LEN, pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, pub_key_x, NULL,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_decode_public_key_test_malformed_zero_data (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, 0, pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_sequence_header_short (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, 1, pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_unknown_sequence_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC521_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC521_PUBKEY_DER, sizeof (der));
	/* Change the length indicator of the SEQUENCE to indicate two length bytes (0x81 -> 0x82). */
	der[1] = 0x82;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNKNOWN_SEQUENCE, status);
}

static void ecc_der_decode_public_key_test_malformed_not_sequence (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the type indicator at the beginning of the buffer. */
	der[0] = 0x03;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_sequence_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the SEQUENCE length to exceed the buffer size. */
	der[1] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_algo_not_sequence (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the type indicator for the AlgorithmIdentifier. */
	der[2] = 0x03;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_algo_sequence_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the AlgorithmIdentifier length to exceed the buffer size. */
	der[3] = (sizeof (der) - 2 - 2) + 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_algo_not_oid (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the type indicator for the algorithm OID. */
	der[4] = 0x03;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_algo_oid_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the AlgorithmIdentifier length to exceed the buffer size. */
	der[5] = (sizeof (der) - 2 - 2 - 2) + 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected length. */
	der[5] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_ALGORITHM, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected value. */
	der[9] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_ALGORITHM, status);
}

static void ecc_der_decode_public_key_test_malformed_curve_not_oid (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the type indicator for the algorithm OID. */
	der[13] = 0x03;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_curve_oid_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the AlgorithmIdentifier length to exceed the buffer size. */
	der[14] = (sizeof (der) - 2 - 2 - 2 - 7 - 2) + 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p256 (
	CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN + 1];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected length. */
	der[14] += 1;
	memmove (&der[24], &der[23], sizeof (der) - 24);

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p256 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected value. */
	der[22] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p384 (
	CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_384];
	uint8_t pub_key_y[ECC_KEY_LENGTH_384];
	int status;
	uint8_t der[ECC384_PUBKEY_DER_LEN + 1];

	TEST_START;

	memcpy (der, ECC384_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected length. */
	der[14] += 1;
	memmove (&der[21], &der[20], sizeof (der) - 21);

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p384 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_384];
	uint8_t pub_key_y[ECC_KEY_LENGTH_384];
	int status;
	uint8_t der[ECC384_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC384_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected value. */
	der[19] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p521 (
	CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_521];
	uint8_t pub_key_y[ECC_KEY_LENGTH_521];
	int status;
	uint8_t der[ECC521_PUBKEY_DER_LEN + 1];

	TEST_START;

	memcpy (der, ECC521_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected length. */
	der[15] += 1;
	memmove (&der[22], &der[21], sizeof (der) - 22);

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}

static void ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p521 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_521];
	uint8_t pub_key_y[ECC_KEY_LENGTH_521];
	int status;
	uint8_t der[ECC521_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC521_PUBKEY_DER, sizeof (der));
	/* Change the algorithm OID to an unexpected value. */
	der[20] += 1;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_CURVE, status);
}
#endif

static void ecc_der_decode_public_key_test_malformed_not_bit_string (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the type indicator for the BIT STRING. */
	der[23] = 0x04;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_malformed_bit_string_too_long (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN + 1];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the BIT STRING length to exceed the buffer size. */
	der[24] += 3;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_public_key_test_unsupported_key_length (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_PUBKEY_DER_LEN + 1];

	TEST_START;

	memcpy (der, ECC_PUBKEY_DER, sizeof (der));
	/* Change the BIT STRING length to an unsupported size. */
	der[24] = ((192 / 8) * 2) + 2;

	status = ecc_der_decode_public_key (der, sizeof (der), pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
}

static void ecc_der_decode_public_key_test_small_key_buffer_p256 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_256];
	uint8_t pub_key_y[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, pub_key_x, pub_key_y,
		ECC_KEY_LENGTH_256 - 1);
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_der_decode_public_key_test_small_key_buffer_p384 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_384];
	uint8_t pub_key_y[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN, pub_key_x,
		pub_key_y, ECC_KEY_LENGTH_384 - 1);
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_decode_public_key_test_small_key_buffer_p521 (CuTest *test)
{
	uint8_t pub_key_x[ECC_KEY_LENGTH_521];
	uint8_t pub_key_y[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_public_key (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN, pub_key_x,
		pub_key_y, ECC_KEY_LENGTH_521 - 1);
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_KEY_BUFFER, status);
}
#endif

static void ecc_der_encode_public_key_test_p256 (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PUBLIC_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, ECC_DER_P256_PUBLIC_LENGTH);

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_public_key_test_p384 (CuTest *test)
{
	uint8_t der[ECC_DER_P384_PUBLIC_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, ECC_DER_P384_PUBLIC_LENGTH);

	status = ecc_der_encode_public_key (ECC384_PUBKEY, &ECC384_PUBKEY[ECC_KEY_LENGTH_384],
		ECC_KEY_LENGTH_384, der, sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC384_PUBKEY_DER, der, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_public_key_test_p521 (CuTest *test)
{
	uint8_t der[ECC_DER_P521_PUBLIC_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC521_PUBKEY_DER_LEN, ECC_DER_P521_PUBLIC_LENGTH);

	status = ecc_der_encode_public_key (ECC521_PUBKEY, &ECC521_PUBKEY[ECC_KEY_LENGTH_521],
		ECC_KEY_LENGTH_521, der, sizeof (der));
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, ECC521_PUBKEY_DER_LEN, status);

	status = testing_validate_array (ECC521_PUBKEY_DER, der, ECC521_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
#endif
}

static void ecc_der_encode_public_key_test_null (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PUBLIC_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (NULL, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_public_key (ECC_PUBKEY, NULL,
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, NULL, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_encode_public_key_test_unsupported_key_length (CuTest *test)
{
	uint8_t der[ECC_DER_P256_PUBLIC_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		(192 / 8), der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_UNSUPPORTED_KEY_LENGTH, status);
}

static void ecc_der_encode_public_key_test_small_buffer_sequence_p256 (CuTest *test)
{
	uint8_t der[1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_der_encode_public_key_test_small_buffer_sequence_p384 (CuTest *test)
{
	uint8_t der[1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC384_PUBKEY, &ECC384_PUBKEY[ECC_KEY_LENGTH_384],
		ECC_KEY_LENGTH_384, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_der_encode_public_key_test_small_buffer_sequence_p521 (CuTest *test)
{
	uint8_t der[2];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC521_PUBKEY, &ECC521_PUBKEY[ECC_KEY_LENGTH_521],
		ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}
#endif

static void ecc_der_encode_public_key_test_small_buffer_algo_sequence (CuTest *test)
{
	uint8_t der[2 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_public_key_test_small_buffer_ec_key_oid (CuTest *test)
{
	uint8_t der[2 + 2 + 2];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_public_key_test_small_buffer_curve_oid (CuTest *test)
{
	uint8_t der[2 + 2 + 2 + 7 + 2 + 7];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_public_key_test_small_buffer_bit_string_tag (CuTest *test)
{
	uint8_t der[2 + 2 + 2 + 7 + 2 + 8 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_public_key_test_small_buffer_bit_string_no_space (CuTest *test)
{
	/* Need an extra byte due to the way length checks are implemented. */
	uint8_t der[2 + 2 + 2 + 7 + 2 + 8 + 2 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_public_key_test_small_buffer_bit_string_short_space (CuTest *test)
{
	uint8_t der[2 + 2 + 2 + 7 + 2 + 8 + 2 + 2 + (ECC_KEY_LENGTH_256 * 2) - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_public_key (ECC_PUBKEY, &ECC_PUBKEY[ECC_KEY_LENGTH_256],
		ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_decode_ecdsa_signature_test_p256 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, sig_r,
		sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST_RAW, sig_r, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], sig_s,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_p384 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_384];
	uint8_t sig_s[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN, sig_r,
		sig_s, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_RAW, sig_r, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC384_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_384], sig_s,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_p521 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_521];
	uint8_t sig_s[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN, sig_r,
		sig_s, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST_RAW, sig_r, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC521_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_521], sig_s,
		ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_no_zero_padding (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN, sig_r,
		sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST2_RAW, sig_r, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&ECC_SIGNATURE_TEST2_RAW[ECC_KEY_LENGTH_256], sig_s,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_minimum_length_p256 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_DER_TESTING_MIN_ECDSA,
		sizeof (ECC_DER_TESTING_MIN_ECDSA), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_DER_TESTING_MIN_ECDSA_R, sig_r, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_DER_TESTING_MIN_ECDSA_S, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_minimum_length_p384 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_384];
	uint8_t sig_s[ECC_KEY_LENGTH_384];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_DER_TESTING_MIN_ECDSA,
		sizeof (ECC_DER_TESTING_MIN_ECDSA), sig_r, sig_s, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_DER_TESTING_MIN_ECDSA_R, sig_r, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_DER_TESTING_MIN_ECDSA_S, sig_s, ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_minimum_length_p521 (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_521];
	uint8_t sig_s[ECC_KEY_LENGTH_521];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_DER_TESTING_MIN_ECDSA,
		sizeof (ECC_DER_TESTING_MIN_ECDSA), sig_r, sig_s, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_DER_TESTING_MIN_ECDSA_R, sig_r, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_DER_TESTING_MIN_ECDSA_S, sig_s, ECC_KEY_LENGTH_521);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_decode_ecdsa_signature_test_null (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (NULL, ECC_SIG_TEST_LEN, sig_r,
		sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, NULL,
		sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, sig_r,
		NULL, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_zero_data (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST, 0, sig_r, sig_s,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_sequence_header_short (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (ECC_SIGNATURE_TEST, 1, sig_r, sig_s,
		ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_unknown_sequence_too_long (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[] = {
		0x30,0x82,0x10,0x20,  // Not valid encoding, but triggers the check against 0x82
		0x02,0x01,0x01,
		0x02,0x01,0x02
	};

	TEST_START;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_UNKNOWN_SEQUENCE, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_not_sequence (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the type indicator at the beginning of the buffer. */
	der[0] = 0x03;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_sequence_too_long (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the SEQUENCE length to exceed the buffer size. */
	der[1] += 1;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_r_not_integer (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the type indicator for the r value. */
	der[2] = 0x03;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_r_integer_too_long (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the r INTEGER length to exceed the buffer size. */
	der[3] = (sizeof (der) - 2 - 2) + 1;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_signature_too_long_r_integer (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the r INTEGER length to be longer than the key size. */
	der[3] = ECC_KEY_LENGTH_256 + 2;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_SIG_TOO_LONG, status);
}

static void ecc_der_decode_ecdsa_signature_test_signature_too_long_r_integer_non_zero_pad (
	CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the r INTEGER padding to be non-zero. */
	der[4] = 1;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_SIG_TOO_LONG, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_s_not_integer (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the type indicator for the s value. */
	der[37] = 0x03;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_malformed_s_integer_too_long (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the s INTEGER length to exceed the buffer size. */
	der[38] = (sizeof (der) - 2 - 2 - 1 - ECC_KEY_LENGTH_256 - 2) + 1;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_MALFORMED, status);
}

static void ecc_der_decode_ecdsa_signature_test_signature_too_long_s_integer (CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN + 1];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the s INTEGER length to be longer than the key size. */
	der[38] = ECC_KEY_LENGTH_256 + 2;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_SIG_TOO_LONG, status);
}

static void ecc_der_decode_ecdsa_signature_test_signature_too_long_s_integer_non_zero_pad (
	CuTest *test)
{
	uint8_t sig_r[ECC_KEY_LENGTH_256];
	uint8_t sig_s[ECC_KEY_LENGTH_256];
	int status;
	uint8_t der[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (der, ECC_SIGNATURE_TEST, sizeof (der));
	/* Change the s INTEGER padding to be non-zero. */
	der[39] = 1;

	status = ecc_der_decode_ecdsa_signature (der, sizeof (der), sig_r, sig_s, ECC_KEY_LENGTH_256);
	CuAssertIntEquals (test, ECC_DER_UTIL_SIG_TOO_LONG, status);
}

static void ecc_der_encode_ecdsa_signature_test_p256 (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, ECC_DER_P256_ECDSA_MAX_LENGTH);

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST, der, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_p384 (CuTest *test)
{
	uint8_t der[ECC_DER_P384_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, ECC_DER_P384_ECDSA_MAX_LENGTH);

	status = ecc_der_encode_ecdsa_signature (ECC384_SIGNATURE_TEST_RAW,
		&ECC384_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_384], ECC_KEY_LENGTH_384, der, sizeof (der));
	CuAssertIntEquals (test, ECC384_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC384_SIGNATURE_TEST, der, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_p521 (CuTest *test)
{
	uint8_t der[ECC_DER_P521_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN + 3, ECC_DER_P521_ECDSA_MAX_LENGTH);

	status = ecc_der_encode_ecdsa_signature (ECC521_SIGNATURE_TEST_RAW,
		&ECC521_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, ECC521_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC521_SIGNATURE_TEST, der, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_no_zero_padding (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST2_RAW,
		&ECC_SIGNATURE_TEST2_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_SIG_TEST2_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST2, der, ECC_SIG_TEST2_LEN);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_minimum_length_p256 (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_DER_TESTING_MIN_ECDSA_R,
		ECC_DER_TESTING_MIN_ECDSA_S, ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (ECC_DER_TESTING_MIN_ECDSA), status);

	status = testing_validate_array (ECC_DER_TESTING_MIN_ECDSA, der, status);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_minimum_length_p384 (CuTest *test)
{
	uint8_t der[ECC_DER_P384_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC384_DER_TESTING_MIN_ECDSA_R,
		ECC384_DER_TESTING_MIN_ECDSA_S, ECC_KEY_LENGTH_384, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (ECC_DER_TESTING_MIN_ECDSA), status);

	status = testing_validate_array (ECC_DER_TESTING_MIN_ECDSA, der, status);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_minimum_length_p521 (CuTest *test)
{
	uint8_t der[ECC_DER_P521_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC521_DER_TESTING_MIN_ECDSA_R,
		ECC521_DER_TESTING_MIN_ECDSA_S, ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (ECC_DER_TESTING_MIN_ECDSA), status);

	status = testing_validate_array (ECC_DER_TESTING_MIN_ECDSA, der, status);
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_minimum_length_integer_zero (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;
	uint8_t expected[] = {
		0x30,0x06,
		0x02,0x01,0x00,		// An INTEGER with value 0.
		0x02,0x01,0x00		// An INTEGER with value 0.
	};
	uint8_t zero[ECC_KEY_LENGTH_256] = {0};

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (zero, zero, ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, der, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_negative_after_leading_zeros (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;
	uint8_t expected[] = {
		0x30,0x08,
		0x02,0x02,0x00,0x80,	// An INTEGER with value 0x80.
		0x02,0x02,0x00,0xaa		// An INTEGER with value 0xaa.
	};
	uint8_t r[ECC_KEY_LENGTH_256] = {0};
	uint8_t s[ECC_KEY_LENGTH_256] = {0};

	TEST_START;

	r[ECC_KEY_LENGTH_256 - 1] = 0x80;
	s[ECC_KEY_LENGTH_256 - 1] = 0xaa;

	status = ecc_der_encode_ecdsa_signature (r, s, ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, sizeof (expected), status);

	status = testing_validate_array (expected, der, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void ecc_der_encode_ecdsa_signature_test_null (CuTest *test)
{
	uint8_t der[ECC_DER_P256_ECDSA_MAX_LENGTH];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (NULL,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		NULL, ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], 0, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, NULL, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_INVALID_ARGUMENT, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_sequence (CuTest *test)
{
	uint8_t der[1];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer (CuTest *test)
{
	uint8_t der[3];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer_padding (CuTest *test)
{
	uint8_t der[4];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer_value (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + ECC_KEY_LENGTH_256 - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + ECC_KEY_LENGTH_256 + 1];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer_padding (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + ECC_KEY_LENGTH_256 + 2];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer_value (CuTest *test)
{
	uint8_t der[2 + 2 + 1 + ECC_KEY_LENGTH_256 + 2 + 1 + ECC_KEY_LENGTH_256 - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC_SIGNATURE_TEST_RAW,
		&ECC_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_256], ECC_KEY_LENGTH_256, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}

static void ecc_der_encode_ecdsa_signature_test_small_buffer_p521_sequence_header (CuTest *test)
{
	uint8_t der[ECC521_SIG_TEST_LEN - 1];
	int status;

	TEST_START;

	status = ecc_der_encode_ecdsa_signature (ECC521_SIGNATURE_TEST_RAW,
		&ECC521_SIGNATURE_TEST_RAW[ECC_KEY_LENGTH_521], ECC_KEY_LENGTH_521, der, sizeof (der));
	CuAssertIntEquals (test, ECC_DER_UTIL_SMALL_DER_BUFFER, status);
}


TEST_SUITE_START (ecc_der_util);

TEST (ecc_der_decode_private_key_test_p256);
TEST (ecc_der_decode_private_key_test_p256_no_pubkey);
TEST (ecc_der_decode_private_key_test_p384);
TEST (ecc_der_decode_private_key_test_p384_no_pubkey);
TEST (ecc_der_decode_private_key_test_p521);
TEST (ecc_der_decode_private_key_test_p521_no_leading_zero);
TEST (ecc_der_decode_private_key_test_p521_no_pubkey);
TEST (ecc_der_decode_private_key_test_null);
TEST (ecc_der_decode_private_key_test_malformed_zero_data);
TEST (ecc_der_decode_private_key_test_malformed_sequence_header_short);
TEST (ecc_der_decode_private_key_test_unknown_sequence_too_long);
TEST (ecc_der_decode_private_key_test_malformed_not_sequence);
TEST (ecc_der_decode_private_key_test_malformed_sequence_too_long);
TEST (ecc_der_decode_private_key_test_malformed_not_integer);
TEST (ecc_der_decode_private_key_test_malformed_integer_too_long);
TEST (ecc_der_decode_private_key_test_unknown_sequence_version_too_long);
TEST (ecc_der_decode_private_key_test_unknown_sequence_not_version_1);
TEST (ecc_der_decode_private_key_test_malformed_not_octet_string);
TEST (ecc_der_decode_private_key_test_malformed_octet_string_too_long);
TEST (ecc_der_decode_private_key_test_unsupported_key_length);
TEST (ecc_der_decode_private_key_test_malformed_not_explicit_parameters);
TEST (ecc_der_decode_private_key_test_malformed_explicit_parameters_too_long);
TEST (ecc_der_decode_private_key_test_malformed_not_oid);
TEST (ecc_der_decode_private_key_test_malformed_oid_too_long);
TEST (ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p256);
TEST (ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p256);
TEST (ecc_der_decode_private_key_test_small_key_buffer_p256);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p384);
TEST (ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p384);
TEST (ecc_der_decode_private_key_test_small_key_buffer_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_decode_private_key_test_unsupported_curve_incorrect_length_p521);
TEST (ecc_der_decode_private_key_test_unsupported_curve_mismatch_oid_p521);
TEST (ecc_der_decode_private_key_test_small_key_buffer_p521);
TEST (ecc_der_decode_private_key_test_small_key_buffer_p521_no_leading_zero);
#endif
TEST (ecc_der_encode_private_key_test_p256);
TEST (ecc_der_encode_private_key_test_p256_no_pubkey);
TEST (ecc_der_encode_private_key_test_p384);
TEST (ecc_der_encode_private_key_test_p384_no_pubkey);
TEST (ecc_der_encode_private_key_test_p521);
TEST (ecc_der_encode_private_key_test_p521_no_pubkey);
TEST (ecc_der_encode_private_key_test_null);
TEST (ecc_der_encode_private_key_test_unsupported_key_length);
TEST (ecc_der_encode_private_key_test_small_buffer_sequence_p256);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_der_encode_private_key_test_small_buffer_sequence_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_encode_private_key_test_small_buffer_sequence_p521);
#endif
TEST (ecc_der_encode_private_key_test_small_buffer_version);
TEST (ecc_der_encode_private_key_test_small_buffer_priv_key);
TEST (ecc_der_encode_private_key_test_small_buffer_explicit_oid);
TEST (ecc_der_encode_private_key_test_small_buffer_oid);
TEST (ecc_der_encode_private_key_test_small_buffer_explicit_pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_encode_private_key_test_small_buffer_explicit_pub_key_p521);
#endif
TEST (ecc_der_encode_private_key_test_small_buffer_bit_string_tag);
TEST (ecc_der_encode_private_key_test_small_buffer_bit_string_no_space);
TEST (ecc_der_encode_private_key_test_small_buffer_bit_string_short_space);
TEST (ecc_der_decode_public_key_test_p256);
TEST (ecc_der_decode_public_key_test_p384);
TEST (ecc_der_decode_public_key_test_p521);
TEST (ecc_der_decode_public_key_test_null);
TEST (ecc_der_decode_public_key_test_malformed_zero_data);
TEST (ecc_der_decode_public_key_test_malformed_sequence_header_short);
TEST (ecc_der_decode_public_key_test_unknown_sequence_too_long);
TEST (ecc_der_decode_public_key_test_malformed_not_sequence);
TEST (ecc_der_decode_public_key_test_malformed_sequence_too_long);
TEST (ecc_der_decode_public_key_test_malformed_algo_not_sequence);
TEST (ecc_der_decode_public_key_test_malformed_algo_sequence_too_long);
TEST (ecc_der_decode_public_key_test_malformed_algo_not_oid);
TEST (ecc_der_decode_public_key_test_malformed_algo_oid_too_long);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid);
TEST (ecc_der_decode_public_key_test_malformed_curve_not_oid);
TEST (ecc_der_decode_public_key_test_malformed_curve_oid_too_long);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p256);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p256);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p384);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_incorrect_length_p521);
TEST (ecc_der_decode_public_key_test_unsupported_algorithm_mismatch_oid_p521);
#endif
TEST (ecc_der_decode_public_key_test_malformed_not_bit_string);
TEST (ecc_der_decode_public_key_test_malformed_bit_string_too_long);
TEST (ecc_der_decode_public_key_test_unsupported_key_length);
TEST (ecc_der_decode_public_key_test_small_key_buffer_p256);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_der_decode_public_key_test_small_key_buffer_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_decode_public_key_test_small_key_buffer_p521);
#endif
TEST (ecc_der_encode_public_key_test_p256);
TEST (ecc_der_encode_public_key_test_p384);
TEST (ecc_der_encode_public_key_test_p521);
TEST (ecc_der_encode_public_key_test_null);
TEST (ecc_der_encode_public_key_test_unsupported_key_length);
TEST (ecc_der_encode_public_key_test_small_buffer_sequence_p256);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_der_encode_public_key_test_small_buffer_sequence_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_der_encode_public_key_test_small_buffer_sequence_p521);
#endif
TEST (ecc_der_encode_public_key_test_small_buffer_algo_sequence);
TEST (ecc_der_encode_public_key_test_small_buffer_ec_key_oid);
TEST (ecc_der_encode_public_key_test_small_buffer_curve_oid);
TEST (ecc_der_encode_public_key_test_small_buffer_bit_string_tag);
TEST (ecc_der_encode_public_key_test_small_buffer_bit_string_no_space);
TEST (ecc_der_encode_public_key_test_small_buffer_bit_string_short_space);
TEST (ecc_der_decode_ecdsa_signature_test_p256);
TEST (ecc_der_decode_ecdsa_signature_test_p384);
TEST (ecc_der_decode_ecdsa_signature_test_p521);
TEST (ecc_der_decode_ecdsa_signature_test_no_zero_padding);
TEST (ecc_der_decode_ecdsa_signature_test_minimum_length_p256);
TEST (ecc_der_decode_ecdsa_signature_test_minimum_length_p384);
TEST (ecc_der_decode_ecdsa_signature_test_minimum_length_p521);
TEST (ecc_der_decode_ecdsa_signature_test_null);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_zero_data);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_sequence_header_short);
TEST (ecc_der_decode_ecdsa_signature_test_unknown_sequence_too_long);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_not_sequence);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_sequence_too_long);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_r_not_integer);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_r_integer_too_long);
TEST (ecc_der_decode_ecdsa_signature_test_signature_too_long_r_integer);
TEST (ecc_der_decode_ecdsa_signature_test_signature_too_long_r_integer_non_zero_pad);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_s_not_integer);
TEST (ecc_der_decode_ecdsa_signature_test_malformed_s_integer_too_long);
TEST (ecc_der_decode_ecdsa_signature_test_signature_too_long_s_integer);
TEST (ecc_der_decode_ecdsa_signature_test_signature_too_long_s_integer_non_zero_pad);
TEST (ecc_der_encode_ecdsa_signature_test_p256);
TEST (ecc_der_encode_ecdsa_signature_test_p384);
TEST (ecc_der_encode_ecdsa_signature_test_p521);
TEST (ecc_der_encode_ecdsa_signature_test_no_zero_padding);
TEST (ecc_der_encode_ecdsa_signature_test_minimum_length_p256);
TEST (ecc_der_encode_ecdsa_signature_test_minimum_length_p384);
TEST (ecc_der_encode_ecdsa_signature_test_minimum_length_p521);
TEST (ecc_der_encode_ecdsa_signature_test_minimum_length_integer_zero);
TEST (ecc_der_encode_ecdsa_signature_test_negative_after_leading_zeros);
TEST (ecc_der_encode_ecdsa_signature_test_null);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_sequence);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer_padding);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_r_integer_value);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer_padding);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_s_integer_value);
TEST (ecc_der_encode_ecdsa_signature_test_small_buffer_p521_sequence_header);

TEST_SUITE_END;
