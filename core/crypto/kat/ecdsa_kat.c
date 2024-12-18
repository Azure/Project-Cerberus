// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "ecc_kat_vectors.h"
#include "ecdsa_kat.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "crypto/signature_verification.h"


/**
 * Random number generator that will produce a fixed set of random data.  This provides a mechanism
 * to get a known k value during ECDSA signature generation self-tests.
 */
struct ecdsa_kat_rng {
	struct rng_engine base;	/**< Base RNG API. */
	const uint8_t *data;	/**< Buffer containing the data to provide when requested. */
	size_t length;			/**< Length of the random data. */
};


static int ecdsa_kat_rng_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	const struct ecdsa_kat_rng *rng = (const struct ecdsa_kat_rng*) engine;

	/* Copy up to the maximum provided by the KAT RNG.  If more data is requested than is available,
	 * which won't be the case in properly functioning implementations, the rest of the output
	 * buffer is left unchanged. */
	buffer_copy (rng->data, rng->length, NULL, &rand_len, buf);

	return 0;
}

/**
 * Initialize a RNG for ECDSA signature generation self-tests.
 */
#define	ecdsa_kat_rng_static_init(data_ptr, length_arg) {\
		.base = { \
			.generate_random_buffer = ecdsa_kat_rng_generate_random_buffer \
		}, \
		.data = data_ptr, \
		.length = length_arg \
	}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-256 and SHA-256.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_p256_sha256 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
	int status;

	status = ecdsa_verify_message (ecc, hash, HASH_TYPE_SHA256, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P256_VERIFY_SELF_TEST_FAILED;
	}

	return status;
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-384 and SHA-384.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_p384_sha384 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	int status;

	status = ecdsa_verify_message (ecc, hash, HASH_TYPE_SHA384, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P384_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecc);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-521 and SHA-512.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_p521_sha512 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	int status;

	status = ecdsa_verify_message (ecc, hash, HASH_TYPE_SHA512, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P521_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecc);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-256 and SHA-256
 * without completing the active hash context.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_hash_p256_sha256 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha256 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = ecdsa_verify_hash (ecc, hash, HASH_TYPE_SHA256, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P256_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-384 and SHA-384
 * without completing the active hash context.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_hash_p384_sha384 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha384 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = ecdsa_verify_hash (ecc, hash, HASH_TYPE_SHA384, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P384_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (ecc);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-521 and SHA-512
 * without completing the active hash context.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc The ECC engine to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_verify_hash_p521_sha512 (const struct ecc_engine *ecc,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha512 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = ecdsa_verify_hash (ecc, hash, HASH_TYPE_SHA512, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P521_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (ecc);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature generation directly against an ECC hardware
 * driver interface using ECC P-256 and SHA-256.
 *
 * It's only necessary to run an ECDSA signature generation self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_sign_p256_sha256 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
	struct ecdsa_kat_rng rng =
		ecdsa_kat_rng_static_init (ECC_KAT_VECTORS_P256_SHA256_ECDSA_K, ECC_KEY_LENGTH_256);
	struct ecc_ecdsa_signature signature = {0};
	int status;

	status = ecdsa_ecc_hw_sign_message (ecc_hw, hash, HASH_TYPE_SHA256, &rng.base,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, &signature);
	if (status != 0) {
		return status;
	}

	if (signature.length != ECC_KEY_LENGTH_256) {
		return ECDSA_P256_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE.r, signature.r,
		ECC_KEY_LENGTH_256) != 0) {
		return ECDSA_P256_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE.s, signature.s,
		ECC_KEY_LENGTH_256) != 0) {
		return ECDSA_P256_SIGN_SELF_TEST_FAILED;
	}

	return 0;
}

/**
 * Run an ECDSA known answer test (KAT) for signature generation directly against an ECC hardware
 * driver interface using ECC P-384 and SHA-384.
 *
 * It's only necessary to run an ECDSA signature generation self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_sign_p384_sha384 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	struct ecdsa_kat_rng rng =
		ecdsa_kat_rng_static_init (ECC_KAT_VECTORS_P384_SHA384_ECDSA_K, ECC_KEY_LENGTH_384);
	struct ecc_ecdsa_signature signature = {0};
	int status;

	status = ecdsa_ecc_hw_sign_message (ecc_hw, hash, HASH_TYPE_SHA384, &rng.base,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, &signature);
	if (status != 0) {
		return status;
	}

	if (signature.length != ECC_KEY_LENGTH_384) {
		return ECDSA_P384_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE.r, signature.r,
		ECC_KEY_LENGTH_384) != 0) {
		return ECDSA_P384_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE.s, signature.s,
		ECC_KEY_LENGTH_384) != 0) {
		return ECDSA_P384_SIGN_SELF_TEST_FAILED;
	}

	return 0;
#else
	UNUSED (ecc_hw);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature generation directly against an ECC hardware
 * driver interface using ECC P-521 and SHA-512.
 *
 * It's only necessary to run an ECDSA signature generation self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_sign_p521_sha512 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	struct ecdsa_kat_rng rng =
		ecdsa_kat_rng_static_init (ECC_KAT_VECTORS_P521_SHA512_ECDSA_K, ECC_KEY_LENGTH_521);
	struct ecc_ecdsa_signature signature = {0};
	int status;

	status = ecdsa_ecc_hw_sign_message (ecc_hw, hash, HASH_TYPE_SHA512, &rng.base,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN, &signature);
	if (status != 0) {
		return status;
	}

	if (signature.length != ECC_KEY_LENGTH_521) {
		return ECDSA_P521_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE.r, signature.r,
		ECC_KEY_LENGTH_521) != 0) {
		return ECDSA_P521_SIGN_SELF_TEST_FAILED;
	}

	if (buffer_compare (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE.s, signature.s,
		ECC_KEY_LENGTH_521) != 0) {
		return ECDSA_P521_SIGN_SELF_TEST_FAILED;
	}

	return 0;
#else
	UNUSED (ecc_hw);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification directly against an ECC hardware
 * driver interface using ECC P-256 and SHA-256.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_verify_p256_sha256 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
	int status;

	status = ecdsa_ecc_hw_verify_message (ecc_hw, hash, HASH_TYPE_SHA256,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		&ECC_KAT_VECTORS_P256_ECC_PUBLIC, &ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE);
	if (status == ECC_HW_ECDSA_BAD_SIGNATURE) {
		status = ECDSA_P256_VERIFY_SELF_TEST_FAILED;
	}

	return status;
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification directly against an ECC hardware
 * driver interface using ECC P-384 and SHA-384.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_verify_p384_sha384 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	int status;

	status = ecdsa_ecc_hw_verify_message (ecc_hw, hash, HASH_TYPE_SHA384,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		&ECC_KAT_VECTORS_P384_ECC_PUBLIC, &ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE);
	if (status == ECC_HW_ECDSA_BAD_SIGNATURE) {
		status = ECDSA_P384_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecc_hw);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an ECDSA known answer test (KAT) for signature verification directly against an ECC hardware
 * driver interface using ECC P-521 and SHA-512.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecc_hw The ECC hardware instance to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int ecdsa_kat_run_self_test_ecc_hw_verify_p521_sha512 (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	int status;

	status = ecdsa_ecc_hw_verify_message (ecc_hw, hash, HASH_TYPE_SHA512,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		&ECC_KAT_VECTORS_P521_ECC_PUBLIC, &ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE);
	if (status == ECC_HW_ECDSA_BAD_SIGNATURE) {
		status = ECDSA_P521_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecc_hw);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}
