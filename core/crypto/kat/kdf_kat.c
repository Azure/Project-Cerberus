// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "kdf_kat.h"
#include "common/buffer_util.h"
#include "crypto/kat/kdf_kat_vectors.h"


/**
 * Run known answer test (KAT) for the NIST800-108 KDF algorithm using SHA-1 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_nist800_108_counter_mode_sha1 (const struct hash_engine *hash)
{
	uint8_t ko[KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KO_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA1, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KI,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KI_LEN, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_CONTEXT_LEN, ko, sizeof (ko));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (ko, KDF_KAT_VECTORS_NIST800_108_CTR_SHA1_KO, sizeof (ko));
	if (status != 0) {
		return KDF_NIST800_108_SHA1_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the NIST800-108 KDF algorithm using SHA-256 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_nist800_108_counter_mode_sha256 (const struct hash_engine *hash)
{
	uint8_t ko[KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KO_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA256,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KI_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_CONTEXT_LEN, ko, sizeof (ko));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (ko, KDF_KAT_VECTORS_NIST800_108_CTR_SHA256_KO, sizeof (ko));
	if (status != 0) {
		return KDF_NIST800_108_SHA256_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the NIST800-108 KDF algorithm using SHA-384 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_nist800_108_counter_mode_sha384 (const struct hash_engine *hash)
{
	uint8_t ko[KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KO_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA384,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KI_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_CONTEXT_LEN, ko, sizeof (ko));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (ko, KDF_KAT_VECTORS_NIST800_108_CTR_SHA384_KO, sizeof (ko));
	if (status != 0) {
		return KDF_NIST800_108_SHA384_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the NIST800-108 KDF algorithm using SHA-512 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_nist800_108_counter_mode_sha512 (const struct hash_engine *hash)
{
	uint8_t ko[KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KO_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_nist800_108_counter_mode (hash, HMAC_SHA512,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KI, KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KI_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_LABEL,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_LABEL_LEN,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_CONTEXT,
		KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_CONTEXT_LEN, ko, sizeof (ko));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (ko, KDF_KAT_VECTORS_NIST800_108_CTR_SHA512_KO, sizeof (ko));
	if (status != 0) {
		return KDF_NIST800_108_SHA512_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the HKDF-Expand KDF algorithm using SHA-1 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_hkdf_expand_sha1 (const struct hash_engine *hash)
{
	uint8_t okm[KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_hkdf_expand (hash, HMAC_SHA1, KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_PRK,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_PRK_LEN, KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (okm, KDF_KAT_VECTORS_HKDF_EXPAND_SHA1_OKM, sizeof (okm));
	if (status != 0) {
		return KDF_HKDF_EXPAND_SHA1_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the HKDF-Expand KDF algorithm using SHA-256 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_hkdf_expand_sha256 (const struct hash_engine *hash)
{
	uint8_t okm[KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_hkdf_expand (hash, HMAC_SHA256, KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_PRK,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_PRK_LEN, KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (okm, KDF_KAT_VECTORS_HKDF_EXPAND_SHA256_OKM, sizeof (okm));
	if (status != 0) {
		return KDF_HKDF_EXPAND_SHA256_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the HKDF-Expand KDF algorithm using SHA-384 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_hkdf_expand_sha384 (const struct hash_engine *hash)
{
	uint8_t okm[KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_hkdf_expand (hash, HMAC_SHA384, KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_PRK,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_PRK_LEN, KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (okm, KDF_KAT_VECTORS_HKDF_EXPAND_SHA384_OKM, sizeof (okm));
	if (status != 0) {
		return KDF_HKDF_EXPAND_SHA384_KAT_FAILED;
	}

	return 0;
}

/**
 * Run known answer test (KAT) for the HKDF-Expand KDF algorithm using SHA-512 HMAC.
 *
 * @param hash The hash engine to use for the self test.
 *
 * @return 0 if the test passed successfully or an error code.
 */
int kdf_kat_run_self_test_hkdf_expand_sha512 (const struct hash_engine *hash)
{
	uint8_t okm[KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM_LEN] = {0};
	int status;

	if (hash == NULL) {
		return KDF_INVALID_ARGUMENT;
	}

	status = kdf_hkdf_expand (hash, HMAC_SHA512, KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_PRK,
		KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_PRK_LEN, KDF_KAT_VECTORS_HKDF_EXPAND_INFO,
		KDF_KAT_VECTORS_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (okm, KDF_KAT_VECTORS_HKDF_EXPAND_SHA512_OKM, sizeof (okm));
	if (status != 0) {
		return KDF_HKDF_EXPAND_SHA512_KAT_FAILED;
	}

	return 0;
}
