// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "crypto/kat/ecdsa_kat.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("ecdsa_kat");


/**
 * Context for verifying the expected k value.
 */
struct ecdsa_kat_testing_k {
	CuTest *test;				/**< The test framework. */
	const uint8_t *expected;	/**< The value expected to be produced by the RNG. */
	size_t length;				/**< Length of the expected value. */
};


/**
 * Mock callback to confirm the RNG provided to a sign KAT generates the expected k value.
 *
 * @param expected The expected data for the call, including the k value to verify against.
 * @param called The arguments for the call, including the RNG instance passed to the function.
 *
 * @return 0 if the RNG generates the expected value.  The function won't return if the RNG data
 * doesn't match.
 */
int64_t ecdsa_kat_testing_check_expected_k (const struct mock_call *expected,
	const struct mock_call *called)
{
	struct ecdsa_kat_testing_k *k = expected->context;
	struct rng_engine *rng = (void*) ((uintptr_t) called->argv[4].value);
	uint8_t rng_out[ECC_KEY_LENGTH_521];
	int status;

	CuAssertPtrNotNull (k->test, rng);
	CuAssertTrue (k->test, (k->length <= sizeof (rng_out)));

	status = rng->generate_random_buffer (rng, k->length, rng_out);
	CuAssertIntEquals (k->test, 0, status);

	status = testing_validate_array (k->expected, rng_out, k->length);
	CuAssertIntEquals (k->test, 0, status);

	return 0;
}


/*******************
 * Test cases
 *******************/

static void ecdsa_kat_test_verify_kat_vectors_p256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	ECC_TESTING_ENGINE (ecc);
	struct ecc_public_key pub_key;
	uint8_t priv_raw[ECC_KEY_LENGTH_256];
	struct ecc_point_public_key pub_raw;
	struct ecc_ecdsa_signature sig_raw;
	uint8_t digest[SHA256_HASH_LENGTH];
	uint8_t *der;
	size_t der_length;
	int status;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	/* Verify that the signature is correct for the data and public key. */
	status = hash.base.calculate_sha256 (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.init_public_key (&ecc.base, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.verify (&ecc.base, &pub_key, digest, sizeof (digest),
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);

	/* Verify that the public key matches the private key. */
	status = ecc.base.init_key_pair (&ecc.base, ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_public_key_der (&ecc.base, &pub_key, &der, &der_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN, der_length);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER, der, der_length);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);
	platform_free (der);

	/* Verify that the raw data matches the DER encoded data. */
	status = ecc_der_decode_private_key (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, sizeof (priv_raw), status);

	status = ecc_der_decode_public_key (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN, pub_raw.x, pub_raw.y, sizeof (pub_raw.x));
	CuAssertIntEquals (test, sizeof (priv_raw), status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P256_ECC_PUBLIC.key_length);

	status = ecc_der_decode_ecdsa_signature (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN, sig_raw.r, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE.length);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_ECC_PRIVATE, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_ECC_PUBLIC.x, pub_raw.x,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_ECC_PUBLIC.y, pub_raw.y,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE.r, sig_raw.r,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE.s, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdsa_kat_test_verify_kat_vectors_p384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	ECC_TESTING_ENGINE (ecc);
	struct ecc_public_key pub_key;
	uint8_t priv_raw[ECC_KEY_LENGTH_384];
	struct ecc_point_public_key pub_raw;
	struct ecc_ecdsa_signature sig_raw;
	uint8_t digest[SHA384_HASH_LENGTH];
	uint8_t *der;
	size_t der_length;
	int status;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	/* Verify that the signature is correct for the data and public key. */
	status = hash.base.calculate_sha384 (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.init_public_key (&ecc.base, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.verify (&ecc.base, &pub_key, digest, sizeof (digest),
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);

	/* Verify that the public key matches the private key. */
	status = ecc.base.init_key_pair (&ecc.base, ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_public_key_der (&ecc.base, &pub_key, &der, &der_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, der_length);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER, der, der_length);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);
	platform_free (der);

	/* Verify that the raw data matches the DER encoded data. */
	status = ecc_der_decode_private_key (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, sizeof (priv_raw), status);

	status = ecc_der_decode_public_key (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, pub_raw.x, pub_raw.y, sizeof (pub_raw.x));
	CuAssertIntEquals (test, sizeof (priv_raw), status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P384_ECC_PUBLIC.key_length);

	status = ecc_der_decode_ecdsa_signature (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN, sig_raw.r, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE.length);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_ECC_PRIVATE, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_ECC_PUBLIC.x, pub_raw.x,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_ECC_PUBLIC.y, pub_raw.y,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE.r, sig_raw.r,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE.s, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdsa_kat_test_verify_kat_vectors_p521 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	ECC_TESTING_ENGINE (ecc);
	struct ecc_public_key pub_key;
	uint8_t priv_raw[ECC_KEY_LENGTH_521];
	struct ecc_point_public_key pub_raw;
	struct ecc_ecdsa_signature sig_raw;
	uint8_t digest[SHA512_HASH_LENGTH];
	uint8_t *der;
	size_t der_length;
	int status;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	/* Verify that the signature is correct for the data and public key. */
	status = hash.base.calculate_sha512 (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.init_public_key (&ecc.base, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.verify (&ecc.base, &pub_key, digest, sizeof (digest),
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);

	/* Verify that the public key matches the private key. */
	status = ecc.base.init_key_pair (&ecc.base, ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.get_public_key_der (&ecc.base, &pub_key, &der, &der_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, der_length);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER, der, der_length);
	CuAssertIntEquals (test, 0, status);

	ecc.base.release_key_pair (&ecc.base, NULL, &pub_key);
	platform_free (der);

	/* Verify that the raw data matches the DER encoded data. */
	status = ecc_der_decode_private_key (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, sizeof (priv_raw), status);

	status = ecc_der_decode_public_key (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, pub_raw.x, pub_raw.y, sizeof (pub_raw.x));
	CuAssertIntEquals (test, sizeof (priv_raw), status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P521_ECC_PUBLIC.key_length);

	status = ecc_der_decode_ecdsa_signature (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN, sig_raw.r, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (priv_raw), ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE.length);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_ECC_PRIVATE, priv_raw, sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_ECC_PUBLIC.x, pub_raw.x,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_ECC_PUBLIC.y, pub_raw.y,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE.r, sig_raw.r,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE.s, sig_raw.s,
		sizeof (priv_raw));
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P256_SHA256_ECDSA_K,
		.length = ECC_KEY_LENGTH_256
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE,
		sizeof (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P256_SHA256_ECDSA_K,
		.length = ECC_KEY_LENGTH_256
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.length -= 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P256_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_r (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P256_SHA256_ECDSA_K,
		.length = ECC_KEY_LENGTH_256
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.r[16] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P256_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_s (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P256_SHA256_ECDSA_K,
		.length = ECC_KEY_LENGTH_256
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.s[24] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P256_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, ECC_HW_ECDSA_SIGN_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_SIGN_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P384_SHA384_ECDSA_K,
		.length = ECC_KEY_LENGTH_384
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE,
		sizeof (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P384_SHA384_ECDSA_K,
		.length = ECC_KEY_LENGTH_384
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.length -= 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P384_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_r (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P384_SHA384_ECDSA_K,
		.length = ECC_KEY_LENGTH_384
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.r[16] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P384_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_s (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P384_SHA384_ECDSA_K,
		.length = ECC_KEY_LENGTH_384
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.s[24] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P384_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, ECC_HW_ECDSA_SIGN_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_SIGN_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P521_SHA512_ECDSA_K,
		.length = ECC_KEY_LENGTH_521
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE,
		sizeof (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P521_SHA512_ECDSA_K,
		.length = ECC_KEY_LENGTH_521
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.length -= 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P521_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_r (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P521_SHA512_ECDSA_K,
		.length = ECC_KEY_LENGTH_521
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.r[16] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P521_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_s (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;
	struct ecdsa_kat_testing_k k = {
		.test = test,
		.expected = ECC_KAT_VECTORS_P521_SHA512_ECDSA_K,
		.length = ECC_KEY_LENGTH_521
	};
	struct ecc_ecdsa_signature bad_sig;

	TEST_START;

	memcpy (&bad_sig, &ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (bad_sig));
	bad_sig.s[24] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecc_hw.mock, 5, &bad_sig, sizeof (bad_sig), -1);
	status |= mock_expect_external_action (&ecc_hw.mock, ecdsa_kat_testing_check_expected_k, &k);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P521_SIGN_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_sign, &ecc_hw, ECC_HW_ECDSA_SIGN_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_SIGN_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P256_VERIFY_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_VERIFY_FAILED,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_VERIFY_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P384_VERIFY_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_VERIFY_FAILED,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_VERIFY_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw, 0,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_BAD_SIGNATURE,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECDSA_P521_VERIFY_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (NULL, &hash.base);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (&ecc_hw.base, NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct ecc_hw_mock ecc_hw;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdsa_verify, &ecc_hw,
		ECC_HW_ECDSA_VERIFY_FAILED,
		MOCK_ARG_VALIDATOR (ecc_mock_validate_point_public_key, &ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (struct ecc_point_public_key)),
		MOCK_ARG_VALIDATOR (ecc_mock_validate_ecdsa_signature,
		&ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE, sizeof (struct ecc_ecdsa_signature)),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (&ecc_hw.base, &hash.base);
	CuAssertIntEquals (test, ECC_HW_ECDSA_VERIFY_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif


TEST_SUITE_START (ecdsa_kat);

TEST (ecdsa_kat_test_verify_kat_vectors_p256);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdsa_kat_test_verify_kat_vectors_p384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdsa_kat_test_verify_kat_vectors_p521);
#endif
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_length);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_r);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_mismatch_s);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p256_sha256_error);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_length);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_r);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_mismatch_s);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p384_sha384_error);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_length);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_r);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_mismatch_s);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_sign_p521_sha512_error);
#endif
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_bad_signature);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p256_sha256_error);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_bad_signature);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p384_sha384_error);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_bad_signature);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_null);
TEST (ecdsa_kat_test_run_self_test_ecc_hw_verify_p521_sha512_error);
#endif

TEST_SUITE_END;
