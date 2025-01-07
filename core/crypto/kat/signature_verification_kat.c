// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "ecc_kat_vectors.h"
#include "rsa_kat_vectors.h"
#include "signature_verification_kat.h"
#include "signature_verification_kat_vectors.h"
#include "crypto/ecdsa.h"
#include "crypto/rsassa.h"


/**
 * Run an ECDSA known answer test (KAT) for signature verification using ECC P-256 and SHA-256.
 *
 * It's only necessary to run an ECDSA signature verification self-test for a single curve supported
 * by the platform.
 *
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
{
	int status;

	status = signature_verification_verify_message (ecdsa, hash, HASH_TYPE_SHA256,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
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
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	int status;

	status = signature_verification_verify_message (ecdsa, hash, HASH_TYPE_SHA384,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P384_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecdsa);
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
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	int status;

	status = signature_verification_verify_message (ecdsa, hash, HASH_TYPE_SHA512,
		ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P521_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (ecdsa);
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
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
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

	status = signature_verification_verify_hash (ecdsa, hash, ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
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
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
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

	status = signature_verification_verify_hash (ecdsa, hash, ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P384_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (ecdsa);
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
 * @param ecdsa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (
	const struct signature_verification *ecdsa, const struct hash_engine *hash)
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

	status = signature_verification_verify_hash (ecdsa, hash, ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN, ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = ECDSA_P521_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (ecdsa);
	UNUSED (hash);

	return ECDSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and
 * SHA-256.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
	int status;

	status = signature_verification_verify_message (rsassa, hash, HASH_TYPE_SHA256,
		RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

	return status;
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and
 * SHA-384.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#ifdef HASH_ENABLE_SHA384
	int status;

	status = signature_verification_verify_message (rsassa, hash, HASH_TYPE_SHA384,
		RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and
 * SHA-512.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#ifdef HASH_ENABLE_SHA512
	int status;

	status = signature_verification_verify_message (rsassa, hash, HASH_TYPE_SHA512,
		RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 3072-bit key and
 * SHA-384.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
	int status;

	status = signature_verification_verify_message (rsassa, hash, HASH_TYPE_SHA384,
		RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN,
		(uint8_t*) &RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC),
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_3K_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 4096-bit key and
 * SHA-384.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
	int status;

	status = signature_verification_verify_message (rsassa, hash, HASH_TYPE_SHA384,
		RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN,
		(uint8_t*) &RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC),
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_4K_VERIFY_SELF_TEST_FAILED;
	}

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and SHA-256
 * without completing the active hash context.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
	int status;

	if (hash == NULL) {
		return RSASSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha256 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_hash (rsassa, hash,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and SHA-384
 * without completing the active hash context.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#ifdef HASH_ENABLE_SHA384
	int status;

	if (hash == NULL) {
		return RSASSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha384 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_hash (rsassa, hash,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 2048-bit key and SHA-512
 * without completing the active hash context.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#ifdef HASH_ENABLE_SHA512
	int status;

	if (hash == NULL) {
		return RSASSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha512 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_hash (rsassa, hash,
		(uint8_t*) &RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC),
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_2K_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 3072-bit key and SHA-384
 * without completing the active hash context.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
	int status;

	if (hash == NULL) {
		return RSASSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha384 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_hash (rsassa, hash,
		(uint8_t*) &RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC),
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_3K_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Run an RSASSA known answer test (KAT) for signature verification using a 4096-bit key and SHA-384
 * without completing the active hash context.
 *
 * It's only necessary to run an RSASSA signature verification self-test for a single key length
 * supported by the platform.
 *
 * @param rsassa The signature verification context to use for the self-test.
 * @param hash The hash engine to use for the self-test.
 *
 * @return 0 if the self-test completed successfully or an error code.
 */
int signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (
	const struct signature_verification *rsassa, const struct hash_engine *hash)
{
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
	int status;

	if (hash == NULL) {
		return RSASSA_INVALID_ARGUMENT;
	}

	status = hash->start_sha384 (hash);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	if (status != 0) {
		goto exit;
	}

	status = signature_verification_verify_hash (rsassa, hash,
		(uint8_t*) &RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC),
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = RSASSA_4K_VERIFY_SELF_TEST_FAILED;
	}

exit:
	hash->cancel (hash);

	return status;
#else
	UNUSED (rsassa);
	UNUSED (hash);

	return RSASSA_UNSUPPORTED_SELF_TEST;
#endif
}
