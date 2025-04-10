// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "ecc_kat_vectors.h"
#include "ecdh_kat.h"
#include "common/buffer_util.h"

/**
 * Self test function for ECDH 256 bits compute shared secret algorithm.
 *
 * @param ecc - ECC engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_kat_run_self_test_p256 (const struct ecc_engine *ecc)
{
	int status;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	uint8_t shared_secret[ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->init_key_pair (ecc, ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN, &priv_key, &pub_key);
	if (status != 0) {
		return status;
	}

	status = ecc->compute_shared_secret (ecc, &priv_key, &pub_key, shared_secret,
		sizeof (shared_secret));
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P256_SELF_TEST_FAILED;
	}
exit:
	buffer_zeroize (shared_secret, sizeof (shared_secret));
	ecc->release_key_pair (ecc, &priv_key, &pub_key);

	return status;
}

/**
 * Self test function for ECDH 384 bits compute shared secret algorithm.
 *
 * @param ecc - ECC engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_kat_run_self_test_p384 (const struct ecc_engine *ecc)
{
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int status;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	uint8_t shared_secret[ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->init_key_pair (ecc, ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN, &priv_key, &pub_key);
	if (status != 0) {
		return status;
	}

	status = ecc->compute_shared_secret (ecc, &priv_key, &pub_key, shared_secret,
		sizeof (shared_secret));
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P384_SELF_TEST_FAILED;
	}
exit:
	buffer_zeroize (shared_secret, sizeof (shared_secret));
	ecc->release_key_pair (ecc, &priv_key, &pub_key);

	return status;
#else
	UNUSED (ecc);

	return ECDH_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Self test function for ECDH 521 bits compute shared secret algorithm.
 *
 * @param ecc - ECC engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_kat_run_self_test_p521 (const struct ecc_engine *ecc)
{
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	int status;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	uint8_t shared_secret[ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->init_key_pair (ecc, ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN, &priv_key, &pub_key);
	if (status != 0) {
		return status;
	}

	status = ecc->compute_shared_secret (ecc, &priv_key, &pub_key, shared_secret,
		sizeof (shared_secret));
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P521_SELF_TEST_FAILED;
	}
exit:
	buffer_zeroize (shared_secret, sizeof (shared_secret));
	ecc->release_key_pair (ecc, &priv_key, &pub_key);

	return status;
#else
	UNUSED (ecc);

	return ECDH_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Self test function for ECDH 256 bits compute shared secret algorithm.
 *
 * @param ecc - ECC HW engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_hw_kat_run_self_test_p256 (const struct ecc_hw *ecc)
{
	int status;
	uint8_t shared_secret[ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->ecdh_compute (ecc, ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256,
		&ECC_KAT_VECTORS_P256_ECC_PUBLIC, shared_secret, sizeof (shared_secret));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P256_SELF_TEST_FAILED;
	}

	buffer_zeroize (shared_secret, sizeof (shared_secret));

	return status;
}

/**
 * Self test function for ECDH 384 bits compute shared secret algorithm.
 *
 * @param ecc - ECC HW engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_hw_kat_run_self_test_p384 (const struct ecc_hw *ecc)
{
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int status;
	uint8_t shared_secret[ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->ecdh_compute (ecc, ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384,
		&ECC_KAT_VECTORS_P384_ECC_PUBLIC, shared_secret, sizeof (shared_secret));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P384_SELF_TEST_FAILED;
	}

	buffer_zeroize (shared_secret, sizeof (shared_secret));

	return status;
#else
	UNUSED (ecc);

	return ECDH_UNSUPPORTED_SELF_TEST;
#endif
}

/**
 * Self test function for ECDH 521 bits compute shared secret algorithm.
 *
 * @param ecc - ECC HW engine interface.
 *
 * @return 0 on success, error code otherwise
 */
int ecdh_hw_kat_run_self_test_p521 (const struct ecc_hw *ecc)
{
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	int status;
	uint8_t shared_secret[ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN] = {};

	if (ecc == NULL) {
		return ECDH_INVALID_ARGUMENT;
	}

	status = ecc->ecdh_compute (ecc, ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521,
		&ECC_KAT_VECTORS_P521_ECC_PUBLIC, shared_secret, sizeof (shared_secret));
	if (status != 0) {
		return status;
	}

	status = buffer_compare (shared_secret, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		sizeof (shared_secret));

	if (status != 0) {
		status = ECDH_P521_SELF_TEST_FAILED;
	}

	buffer_zeroize (shared_secret, sizeof (shared_secret));

	return status;
#else
	UNUSED (ecc);

	return ECDH_UNSUPPORTED_SELF_TEST;
#endif
}
