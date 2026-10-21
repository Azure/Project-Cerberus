// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "ecdh.h"
#include "common/buffer_util.h"
#include "crypto/kat/ecc_kat_vectors.h"


#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
/**
 * Global flag that will be used to trigger a PCT failure for a single generated ECDH key pair when
 * using the ECC engine API.  Triggering this failure is necessary to support FIPS CMVP testing for
 * certification.
 */
bool ecdh_fail_pct;

/**
 * Global flag that will be used to trigger a PCT failure for a single generated ECDH key pair when
 * using the direct ECC hardware API.  Triggering this failure is necessary to support FIPS CMVP
 * testing for certification.
 */
bool ecdh_hw_fail_pct;
#endif


#ifdef ECC_ENABLE_ECDH
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
/**
 * Generate a random ECDH key pair.  A pairwise consistency test (PCT) will be executed for the new
 * key pair.
 *
 * The desired length of the key determines the ECC curve to use for key pair generation.
 *  - ECC_KEY_LENGTH_256 -> NIST P-256
 *  - ECC_KEY_LENGTH_384 -> NIST P-384
 *  - ECC_KEY_LENGTH_521 -> NIST P-521
 *
 * @param ecc The ECC engine to use to generate the key pair.
 * @param key_length The length of the key that should be generated.
 * @param priv_key Output for the generated private key.
 * @param pub_key Output for the generated public key.  This can be null if the public key is not
 * needed.
 *
 * @return 0 if the key pair was successfully generated or an error code.
 */
int ecdh_generate_random_key (const struct ecc_engine *ecc, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_public_key temp_pub;
	int status;

	if ((ecc == NULL) || (priv_key == NULL)) {
		return ECDH_INVALID_ARGUMENT;
	}

	if (pub_key == NULL) {
		pub_key = &temp_pub;
	}

	status = ecc->generate_key_pair (ecc, key_length, priv_key, pub_key);
	if (status != 0) {
		return status;
	}

	status = ecdh_pairwise_consistency_test (ecc, priv_key, pub_key);
	if (status != 0) {
		ecc->release_key_pair (ecc, priv_key, pub_key);
	}
	else if (pub_key == &temp_pub) {
		ecc->release_key_pair (ecc, NULL, &temp_pub);
	}

	return status;
}
#endif	/* ECC_ENABLE_GENERATE_KEY_PAIR */

/**
 * Execute a pairwise consistency test (PCT) on an ECDH key pair.
 *
 * @param ecc The ECC engine to use for the PCT.
 * @param priv_key The ECDH private key.
 * @param pub_key The ECDH public key.
 *
 * @return 0 if the PCT passed or an error code.
 */
int ecdh_pairwise_consistency_test (const struct ecc_engine *ecc,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key)
{
	int key_length;
	const uint8_t *pct_der = NULL;
	size_t pct_der_length = 0;
	struct ecc_private_key pct_priv;
	struct ecc_public_key pct_pub;
	uint8_t pct_out_priv[ECC_MAX_KEY_LENGTH] = {0};
	uint8_t pct_out_pub[ECC_MAX_KEY_LENGTH] = {0};
	int pct_out_length;
	int status;

	if ((ecc == NULL) || (priv_key == NULL) || (pub_key == NULL)) {
		return ECDH_INVALID_ARGUMENT;
	}

	key_length = ecc->get_shared_secret_max_length (ecc, priv_key);
	if (ROT_IS_ERROR (key_length)) {
		return key_length;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			pct_der = ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER;
			pct_der_length = ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN;
			break;

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
		case ECC_KEY_LENGTH_384:
			pct_der = ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER;
			pct_der_length = ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN;
			break;
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
		case ECC_KEY_LENGTH_521:
			pct_der = ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER;
			pct_der_length = ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN;
			break;
#endif
	}

	status = ecc->init_key_pair (ecc, pct_der, pct_der_length, &pct_priv, &pct_pub);
	if (status != 0) {
		return status;
	}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
	/* Provide the ability to inject errors into the ECDH PCT to validate negative test scenarios
	 * for FIPS CMVP certification. */
	if (ecdh_fail_pct) {
		switch (key_length) {
			case ECC_KEY_LENGTH_256:
				pct_der = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P256_ECC_PUBLIC_DER;
				pct_der_length = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P256_ECC_PUBLIC_DER_LEN;
				break;

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
			case ECC_KEY_LENGTH_384:
				pct_der = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P384_ECC_PUBLIC_DER;
				pct_der_length = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P384_ECC_PUBLIC_DER_LEN;
				break;
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
			case ECC_KEY_LENGTH_521:
				pct_der = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P521_ECC_PUBLIC_DER;
				pct_der_length = ECC_KAT_VECTORS_CMVP_PCT_FAIL_P521_ECC_PUBLIC_DER_LEN;
				break;
#endif
		}

		/* Release the good public key and initialize a key context for a bad one. */
		ecc->release_key_pair (ecc, NULL, &pct_pub);
		ecdh_fail_pct = false;

		status = ecc->init_public_key (ecc, pct_der, pct_der_length, &pct_pub);
		if (status != 0) {
			ecc->release_key_pair (ecc, &pct_priv, NULL);

			return status;
		}
	}
#endif	/* ECDH_ENABLE_FIPS_CMVP_TESTING */

	pct_out_length = ecc->compute_shared_secret (ecc, priv_key, &pct_pub, pct_out_priv,
		sizeof (pct_out_priv));
	if (ROT_IS_ERROR (pct_out_length)) {
		status = pct_out_length;
		goto exit;
	}

	status = ecc->compute_shared_secret (ecc, &pct_priv, pub_key, pct_out_pub,
		sizeof (pct_out_pub));
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}

	if (status != pct_out_length) {
		status = ECDH_PCT_FAILURE;
		goto exit;
	}

	status = buffer_compare (pct_out_priv, pct_out_pub, pct_out_length);
	if (status != 0) {
		status = ECDH_PCT_FAILURE;
	}

exit:
	ecc->release_key_pair (ecc, &pct_priv, &pct_pub);

	buffer_zeroize (pct_out_priv, sizeof (pct_out_priv));
	buffer_zeroize (pct_out_pub, sizeof (pct_out_pub));

	return status;
}
#endif	/* ECC_ENABLE_ECDH */

/**
 * Generate a random ECDH key pair using an ECC hardware implementation.  A pairwise consistency
 * test (PCT) will be executed for the new key pair.
 *
 * The desired length of the key determines the ECC curve to use for key pair generation.
 *  - ECC_KEY_LENGTH_256 -> NIST P-256
 *  - ECC_KEY_LENGTH_384 -> NIST P-384
 *  - ECC_KEY_LENGTH_521 -> NIST P-521
 *
 * @param ecc_hw The ECC HW engine to use for generating the key pair.
 * @param key_length The length of the key that should be generated.
 * @param priv_key Output for the generated private key.
 * @param pub_key Output for the generated public key.  This can be null if the public key is not
 * needed.
 *
 * @return 0 if the key pair was successfully generated or an error code.
 */
int ecdh_ecc_hw_generate_random_key (const struct ecc_hw *ecc_hw, size_t key_length,
	struct ecc_raw_private_key *priv_key, struct ecc_point_public_key *pub_key)
{
	struct ecc_point_public_key temp_pub = {0};
	int status;

	if ((ecc_hw == NULL) || (priv_key == NULL)) {
		return ECDH_INVALID_ARGUMENT;
	}

	if (pub_key == NULL) {
		pub_key = &temp_pub;
	}

	status = ecc_hw->generate_ecc_key_pair (ecc_hw, key_length, priv_key->d, pub_key);
	if (status != 0) {
		return status;
	}

	priv_key->key_length = key_length;

	status = ecdh_ecc_hw_pairwise_consistency_test (ecc_hw, priv_key->d, priv_key->key_length,
		pub_key);
	if (status != 0) {
		buffer_zeroize (priv_key, sizeof (*priv_key));
		buffer_zeroize (pub_key, sizeof (*pub_key));
	}
	else {
		buffer_zeroize (&temp_pub, sizeof (temp_pub));
	}

	return status;
}

/**
 * Execute a pairwise consistency test (PCT) on an ECDH key pair using an ECC hardware
 * implementation.
 *
 * @param ecc_hw The ECC HW engine to use for the PCT.
 * @param priv_key The ECDH private key.
 * @param key_length Length of the private key.
 * @param pub_key The ECDH public key.
 *
 * @return 0 if the PCT passed or an error code.
 */
int ecdh_ecc_hw_pairwise_consistency_test (const struct ecc_hw *ecc_hw, const uint8_t *priv_key,
	size_t key_length, const struct ecc_point_public_key *pub_key)
{
	const uint8_t *pct_priv = NULL;
	const struct ecc_point_public_key *pct_pub = NULL;
	uint8_t pct_out_priv[ECC_MAX_KEY_LENGTH] = {0};
	uint8_t pct_out_pub[ECC_MAX_KEY_LENGTH] = {0};
	int status;

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
	uint8_t bad_priv[ECC_MAX_KEY_LENGTH];
#endif

	if ((ecc_hw == NULL) || (priv_key == NULL) || (pub_key == NULL)) {
		return ECDH_INVALID_ARGUMENT;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			pct_priv = ECC_KAT_VECTORS_P256_ECC_PRIVATE;
			pct_pub = &ECC_KAT_VECTORS_P256_ECC_PUBLIC;
			break;

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
		case ECC_KEY_LENGTH_384:
			pct_priv = ECC_KAT_VECTORS_P384_ECC_PRIVATE;
			pct_pub = &ECC_KAT_VECTORS_P384_ECC_PUBLIC;
			break;
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
		case ECC_KEY_LENGTH_521:
			pct_priv = ECC_KAT_VECTORS_P521_ECC_PRIVATE;
			pct_pub = &ECC_KAT_VECTORS_P521_ECC_PUBLIC;
			break;
#endif

		default:
			return ECDH_UNSUPPORTED_KEY_LENGTH;
	}

	status = ecc_hw->ecdh_compute (ecc_hw, priv_key, key_length, pct_pub, pct_out_priv,
		sizeof (pct_out_priv));
	if (status != 0) {
		goto exit;
	}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
	/* Provide the ability to inject errors into the ECDH PCT to validate negative test scenarios
	 * for FIPS CMVP certification. */
	if (ecdh_hw_fail_pct) {
		memcpy (bad_priv, pct_priv, key_length);
		bad_priv[16] ^= 0x10;
		pct_priv = bad_priv;

		ecdh_hw_fail_pct = false;
	}
#endif

	status = ecc_hw->ecdh_compute (ecc_hw, pct_priv, key_length, pub_key, pct_out_pub,
		sizeof (pct_out_pub));
	if (status != 0) {
		goto exit;
	}

	status = buffer_compare (pct_out_priv, pct_out_pub, key_length);
	if (status != 0) {
		status = ECDH_PCT_FAILURE;
	}

exit:
	buffer_zeroize (pct_out_priv, sizeof (pct_out_priv));
	buffer_zeroize (pct_out_pub, sizeof (pct_out_pub));
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
	buffer_zeroize (bad_priv, sizeof (bad_priv));
#endif

	return status;
}
