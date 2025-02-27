// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "ecdsa.h"
#include "signature_verification_ecc.h"
#include "common/buffer_util.h"
#include "common/common_math.h"


/**
 * Instantiate an HMAC_DRBG per RFC 6979 that can be used for generating the k value needed for
 * ECDSA signatures in a deterministic way.
 *
 * @param drbg The ECDSA DRBG context to instantiate.  This must be wiped using
 * ecdsa_deterministic_k_drbg_clear after the signing process has completed.
 * @param hash The hash engine to used for HMAC operations.
 * @param hmac_algo The HMAC algorithm that should be used by the DRBG.
 * @param message_digest Digest of the message that is being signed with ECDSA.  This can be either
 * the raw digest of the message data or the truncated/padded version used during signature
 * generation.
 * @param digest_length Length of the message digest.
 * @param priv_key The private key being used to sign the message.
 * @param key_length Length of the private key.
 *
 * @return 0 if the ECDSA DRBG was instantiated successfully or an error code.
 */
int ecdsa_deterministic_k_drbg_instantiate (struct ecdsa_deterministic_k_drbg *drbg,
	const struct hash_engine *hash, enum hmac_hash hmac_algo, const uint8_t *message_digest,
	size_t digest_length, const uint8_t *priv_key, size_t key_length)
{
	struct hmac_engine hmac;
	int hash_length;
	uint8_t internal_octet;
	int status;

	if ((drbg == NULL) || (hash == NULL) || (message_digest == NULL) || (priv_key == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	hash_length = hash_hmac_get_hmac_length (hmac_algo);
	if (hash_length == HASH_ENGINE_UNKNOWN_HASH) {
		return hash_length;
	}

	/* Set the initial values for K (0's) and V (1's). */
	memset (drbg->key, 0, sizeof (drbg->key));
	memset (drbg->value, 1, sizeof (drbg->value));
	drbg->first = true;
	drbg->hmac_algo = hmac_algo;

	for (internal_octet = 0; internal_octet < 2; internal_octet++) {
		/* Derive a new K from the private key and message digest. */
		status = hash_hmac_init (&hmac, hash, hmac_algo, drbg->key, hash_length);
		if (status != 0) {
			goto erase_context;
		}

		status = hash_hmac_update (&hmac, drbg->value, hash_length);
		if (status != 0) {
			goto hmac_cancel;
		}

		status = hash_hmac_update (&hmac, &internal_octet, 1);
		if (status != 0) {
			goto hmac_cancel;
		}

		status = hash_hmac_update (&hmac, priv_key, key_length);
		if (status != 0) {
			goto hmac_cancel;
		}

		status = hash_hmac_update (&hmac, message_digest, digest_length);
		if (status != 0) {
			goto hmac_cancel;
		}

		status = hash_hmac_finish (&hmac, drbg->key, sizeof (drbg->key));
		if (status != 0) {
			goto erase_context;
		}

		/* Derive the new V using the updated K. */
		status = hash_generate_hmac (hash, drbg->key, hash_length, drbg->value, hash_length,
			hmac_algo, drbg->value, sizeof (drbg->value));
		if (status != 0) {
			goto erase_context;
		}
	}

	return 0;

hmac_cancel:
	hash_hmac_cancel (&hmac);

erase_context:
	buffer_zeroize (drbg, sizeof (*drbg));

	return status;
}

/**
 * Generate a k value that can be used for ECDSA signatures following the deterministic generation
 * algorithm specified in RFC 6979.  ecdsa_instantiate_deterministic_k_drbg must be called prior to
 * generating any k values.
 *
 * No checking of the resultant value against curve order is done, nor is it proven to generate a
 * valid r value.  It is up to the caller to ensure the generated k value is valid and call this
 * function again if a new k is needed.
 *
 * If this call fails, the DRBG is left in an indeterminate state.  The DRBG context should be
 * cleared and reinstantiated for additional attempts to generate a k value.
 *
 * @param drbg The instantiated DRBG to use for k generation.  The DRBG context will be updated,
 * allowing for multiple calls to be made if invalid k values are produced.
 * @param hash The hash engine to use for HMAC operations.
 * @param k Output for the k value generated by the DRBG.
 * @param k_length The number of bytes to generate for k.
 *
 * @return 0 if k was generated successfully or an error code.
 */
int ecdsa_deterministic_k_drbg_generate (struct ecdsa_deterministic_k_drbg *drbg,
	const struct hash_engine *hash, uint8_t *k, size_t k_length)
{
	struct hmac_engine hmac;
	uint8_t zero = 0x00;
	int hash_length;
	uint8_t *pos = k;
	size_t remaining = k_length;
	int status;

	if ((drbg == NULL) || (hash == NULL) || (k == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	hash_length = hash_hmac_get_hmac_length (drbg->hmac_algo);
	if (hash_length == HASH_ENGINE_UNKNOWN_HASH) {
		return hash_length;
	}

	if (!drbg->first) {
		/* For subsequent requests, new K and V values need to be calculated. */
		status = hash_hmac_init (&hmac, hash, drbg->hmac_algo, drbg->key, hash_length);
		if (status != 0) {
			return status;
		}

		status = hash_hmac_update (&hmac, drbg->value, hash_length);
		if (status != 0) {
			hash_hmac_cancel (&hmac);

			return status;
		}

		status = hash_hmac_update (&hmac, &zero, 1);
		if (status != 0) {
			hash_hmac_cancel (&hmac);

			return status;
		}

		status = hash_hmac_finish (&hmac, drbg->key, sizeof (drbg->key));
		if (status != 0) {
			return status;
		}

		status = hash_generate_hmac (hash, drbg->key, hash_length, drbg->value, hash_length,
			drbg->hmac_algo, drbg->value, sizeof (drbg->value));
		if (status != 0) {
			return status;
		}
	}

	drbg->first = false;

	while (remaining > 0) {
		status = hash_generate_hmac (hash, drbg->key, hash_length, drbg->value, hash_length,
			drbg->hmac_algo, drbg->value, sizeof (drbg->value));
		if (status != 0) {
			return status;
		}

		pos += buffer_copy (drbg->value, hash_length, NULL, &remaining, pos);
	}

	/* When the key length is not an even multiple of bytes, bits need to get dropped from the
	 * generated data.  Per the RFC, this would be the last bits in the array, meaning the entire
	 * array needs to be right shifted. */
	if (k_length == ECC_KEY_LENGTH_521) {
		common_math_right_shift_array (k, k_length, 7);
	}

	return 0;
}

/**
 * Erase the DRBG context used for ECDSA signature k generation.
 *
 * @param drbg The DRBG context to clear.
 */
void ecdsa_deterministic_k_drbg_clear (struct ecdsa_deterministic_k_drbg *drbg)
{
	buffer_zeroize (drbg, sizeof (*drbg));
}

/**
 * Generate an ECDSA signature for a specified message.
 *
 * @param ecc The ECC engine to use for signature generation.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param hash_algo Algorithm to use for message hashing.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC engine will use a default RNG.
 * @param priv_key DER encoded ECC private key to use for signing.
 * @param key_length Length of the ECC private key data.
 * @param message The raw message data that should be signed.
 * @param msg_length Length of the message.
 * @param signature Output buffer for the ECDSA signature.  The signature will be DER encoded.
 * @param sig_length The length of the signature output buffer.
 *
 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int ecdsa_sign_message (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, const uint8_t *message, size_t msg_length, uint8_t *signature,
	size_t sig_length)
{
	int status;

	if ((ecc == NULL) || (hash == NULL) || (priv_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, hash_algo);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, message, msg_length);
	if (status != 0) {
		hash->cancel (hash);

		return status;
	}

	return ecdsa_sign_hash_and_finish (ecc, hash, rng, priv_key, key_length, signature, sig_length);
}

/**
 * Generate an ECDSA signature for the calculated digest.
 *
 * @param ecc The ECC engine to use for signature generation.
 * @param digest The digest to sign.  This will be zeroized upon return.
 * @param digest_length Length of the digest to sign.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC engine will use a default RNG.
 * @param priv_key DER encoded ECC private key to use for signing.
 * @param key_length Length of the ECC private key data.
 * @param signature Output buffer for the ECDSA signature.  The signature will be DER encoded.
 * @param sig_length The length of the signature output buffer.
 *
 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
static int ecdsa_sign_digest (const struct ecc_engine *ecc, uint8_t digest[HASH_MAX_HASH_LEN],
	size_t digest_length, const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	uint8_t *signature, size_t sig_length)
{
	struct ecc_private_key sign_key;
	int status;

	status = ecc->init_key_pair (ecc, priv_key, key_length, &sign_key, NULL);
	if (status != 0) {
		goto exit;
	}

	status = ecc->sign (ecc, &sign_key, digest, digest_length, rng, signature, sig_length);

	ecc->release_key_pair (ecc, &sign_key, NULL);

exit:
	buffer_zeroize (digest, HASH_MAX_HASH_LEN);

	return status;
}

/**
 * Generate an ECDSA signature for an active hash context.
 *
 * The hash context will remain active after signature generation, allowing additional updates to be
 * made.  Not all hash implementations support this type of behavior, so it should only be used in
 * scenarios which require it.  Most scenarios should use ecdsa_sign_hash_and_finish instead.
 *
 * @param ecc The ECC engine to use for signature generation.
 * @param hash The hash engine that contains the active context to sign.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC engine will use a default RNG.
 * @param priv_key DER encoded ECC private key to use for signing.
 * @param key_length Length of the ECC private key.
 * @param signature Output buffer for the ECDSA signature.  The signature will be DER encoded.
 * @param sig_length The length of the signature output buffer.
 *
 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int ecdsa_sign_hash (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length, uint8_t *signature,
	size_t sig_length)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if ((ecc == NULL) || (hash == NULL) || (priv_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	status = hash->get_hash (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);

		return status;
	}

	return ecdsa_sign_digest (ecc, digest, digest_length, rng, priv_key, key_length, signature,
		sig_length);
}

/**
 * Generate an ECDSA signature for an active hash context.
 *
 * The hash context will be finished as part of signature generation.  No additional updates can be
 * made to the hash context, regardless of whether the signature generation was successful or not.
 *
 * @param ecc The ECC engine to use for signature generation.
 * @param hash The hash engine that contains the active context to sign.  The active context will
 * always be terminated upon returning from this call.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC engine will use a default RNG.
 * @param priv_key DER encoded ECC private key to use for signing.
 * @param key_length Length of the ECC private key.
 * @param signature Output buffer for the ECDSA signature.  The signature will be DER encoded.
 * @param sig_length The length of the signature output buffer.
 *
 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
 * value.
 */
int ecdsa_sign_hash_and_finish (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length, uint8_t *signature,
	size_t sig_length)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	if ((ecc == NULL) || (priv_key == NULL) || (signature == NULL)) {
		status = ECDSA_INVALID_ARGUMENT;
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);
		goto hash_cancel;
	}

	return ecdsa_sign_digest (ecc, digest, digest_length, rng, priv_key, key_length, signature,
		sig_length);

hash_cancel:
	hash->cancel (hash);

	return status;
}

/**
 * Verify a specified message with an ECDSA signature.
 *
 * @param ecc The ECC engine to use for ECDSA signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param hash_algo Algorithm to use for message hashing.
 * @param message The raw message data that should be verified.
 * @param msg_length Length of the message.
 * @param pub_key A DER encoded ECC public key to use for verification.  Providing a private key is
 * also supported, though verification will use only the public portion of the key pair.
 * @param key_length Length of the DER encoded ECC key.
 * @param signature The DER encoded ECDSA signature for the message data.
 * @param sig_length Length of the ECDSA signature.
 *
 * @return 0 if the message was verified successfully or an error code.
 */
int ecdsa_verify_message (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length, const uint8_t *pub_key,
	size_t key_length, const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_ecc_state sig_verify_state;
	struct signature_verification_ecc sig_verify;
	int status;

	status = signature_verification_ecc_init (&sig_verify, &sig_verify_state, ecc, pub_key,
		key_length);
	if (status != 0) {
		return status;
	}

	status = signature_verification_verify_message (&sig_verify.base, hash, hash_algo, message,
		msg_length, NULL, 0, signature, sig_length);

	signature_verification_ecc_release (&sig_verify);

	return status;
}

/**
 * Verify an active hash context with an ECDSA signature.
 *
 * The hash context will remain active after signature verification, allowing additional updates to
 * be made.  Not all hash implementations support this type of behavior, so it should only be used
 * in scenarios which require it.  Most scenarios should use ecdsa_verify_hash_and_finish instead.
 *
 * @param ecc The ECC engine to use for ECDSA signature verification.
 * @param hash The hash engine that contains the active context to verify.
 * @param pub_key A DER encoded ECC public key to use for verification.  Providing a private key is
 * also supported, though verification will use only the public portion of the key pair.
 * @param key_length Length of the DER encoded ECC key.
 * @param signature The DER encoded ECDSA signature for the hash context.
 * @param sig_length Length of the ECDSA signature.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int ecdsa_verify_hash (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const uint8_t *pub_key, size_t key_length, const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_ecc_state sig_verify_state;
	struct signature_verification_ecc sig_verify;
	int status;

	status = signature_verification_ecc_init (&sig_verify, &sig_verify_state, ecc, pub_key,
		key_length);
	if (status != 0) {
		return status;
	}

	status = signature_verification_verify_hash (&sig_verify.base, hash, NULL, 0, signature,
		sig_length);

	signature_verification_ecc_release (&sig_verify);

	return status;
}

/**
 * Verify an active hash context with an ECDSA signature.
 *
 * The hash context will be finished as part of signature verification.  No additional updates can
 * be made to the hash context, regardless of whether the signature verification was successful or
 * not.
 *
 * @param ecc The ECC engine to use for ECDSA signature verification.
 * @param hash The hash engine that contains the active context to verify.
 * @param pub_key A DER encoded ECC public key to use for verification.  Providing a private key is
 * also supported, though verification will use only the public portion of the key pair.
 * @param key_length Length of the DER encoded ECC key.
 * @param signature The DER encoded ECDSA signature for the hash context.
 * @param sig_length Length of the ECDSA signature.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int ecdsa_verify_hash_and_finish (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const uint8_t *pub_key, size_t key_length, const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_ecc_state sig_verify_state;
	struct signature_verification_ecc sig_verify;
	int status;

	status = signature_verification_ecc_init (&sig_verify, &sig_verify_state, ecc, pub_key,
		key_length);
	if (status != 0) {
		return status;
	}

	status = signature_verification_verify_hash_and_finish (&sig_verify.base, hash, NULL, 0,
		signature, sig_length);

	signature_verification_ecc_release (&sig_verify);

	return status;
}

/**
 * Generate an ECDSA signature for a specified message using an ECC hardware implementation.
 *
 * @param ecc_hw The ECC hardware instance to use for signature generation.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param hash_algo Algorithm to use for message hashing.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC hardware instance will use a default RNG, if one is
 * available.
 * @param priv_key Raw ECC private key to use for signing.
 * @param key_length Length of the ECC private key.  This will determine the curve to use.
 * @param message The raw message data that should be signed.
 * @param msg_length Length of the message.
 * @param signature Output buffer for the ECDSA signature.
 *
 * @return 0 if the signature was generated successfully or an error code.
 */
int ecdsa_ecc_hw_sign_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, const uint8_t *message, size_t msg_length,
	struct ecc_ecdsa_signature *signature)
{
	int status;

	if ((ecc_hw == NULL) || (hash == NULL) || (priv_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, hash_algo);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, message, msg_length);
	if (status != 0) {
		hash->cancel (hash);

		return status;
	}

	return ecdsa_ecc_hw_sign_hash_and_finish (ecc_hw, hash, rng, priv_key, key_length, signature);
}

/**
 * Generate an ECDSA signature for the calculated digest using an ECC hardware implementation.
 *
 * @param ecc_hw The ECC hardware instance to use for signature generation.
 * @param digest The digest to sign.  This will be zeroized upon return.
 * @param digest_length Length of the digest to sign.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC hardware instance will use a default RNG, if one is
 * available.
 * @param priv_key Raw ECC private key to use for signing.
 * @param key_length Length of the ECC private key.  This will determine the curve to use.
 * @param signature Output buffer for the ECDSA signature.
 *
 * @return 0 if the signature was generated successfully or an error code.
 */
static int ecdsa_ecc_hw_sign_digest (const struct ecc_hw *ecc_hw, uint8_t digest[HASH_MAX_HASH_LEN],
	size_t digest_length, const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	struct ecc_ecdsa_signature *signature)
{
	int status;

	status = ecc_hw->ecdsa_sign (ecc_hw, priv_key, key_length, digest, digest_length, rng,
		signature);

	buffer_zeroize (digest, HASH_MAX_HASH_LEN);

	return status;
}

/**
 * Generate an ECDSA signature for an active hash context using an ECC hardware implementation.
 *
 * The hash context will remain active after signature generation, allowing additional updates to be
 * made.  Not all hash implementations support this type of behavior, so it should only be used in
 * scenarios which require it.  Most scenarios should use ecdsa_ecc_hw_sign_hash_and_finish instead.
 *
 * @param ecc_hw The ECC hardware instance to use for signature generation.
 * @param hash The hash engine that contains the active context to sign.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC hardware instance will use a default RNG, if one is
 * available.
 * @param priv_key Raw ECC private key to use for signing.
 * @param key_length Length of the ECC private key.  This will determine the curve to use.
 * @param signature Output buffer for the ECDSA signature.
 *
 * @return 0 if the signature was generated successfully or an error code.
 */
int ecdsa_ecc_hw_sign_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	struct ecc_ecdsa_signature *signature)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if ((ecc_hw == NULL) || (hash == NULL) || (priv_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	status = hash->get_hash (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);

		return status;
	}

	return ecdsa_ecc_hw_sign_digest (ecc_hw, digest, digest_length, rng, priv_key, key_length,
		signature);
}

/**
 * Generate an ECDSA signature for an active hash context using an ECC hardware implementation.
 *
 * The hash context will be finished as part of signature generation.  No additional updates can be
 * made to the hash context, regardless of whether the signature generation was successful or not.
 *
 * @param ecc_hw The ECC hardware instance to use for signature generation.
 * @param hash The hash engine that contains the active context to sign.  The active context will
 * always be terminated upon returning from this call.
 * @param rng The random number generator that will be used to generate the random 'r' value in the
 * signature.  If this is null, the ECC hardware instance will use a default RNG, if one is
 * available.
 * @param priv_key Raw ECC private key to use for signing.
 * @param key_length Length of the ECC private key.  This will determine the curve to use.
 * @param signature Output buffer for the ECDSA signature.
 *
 * @return 0 if the signature was generated successfully or an error code.
 */
int ecdsa_ecc_hw_sign_hash_and_finish (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	struct ecc_ecdsa_signature *signature)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	if ((ecc_hw == NULL) || (priv_key == NULL) || (signature == NULL)) {
		status = ECDSA_INVALID_ARGUMENT;
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);
		goto hash_cancel;
	}

	return ecdsa_ecc_hw_sign_digest (ecc_hw, digest, digest_length, rng, priv_key, key_length,
		signature);

hash_cancel:
	hash->cancel (hash);

	return status;
}

/**
 * Verify a specified message with an ECDSA signature using an ECC hardware implementation.
 *
 * @param ecc_hw The ECC hardware instance to use for signature verification.
 * @param hash The hash engine that will be used to calculate the message digest.
 * @param hash_algo Algorithm to use for message hashing.
 * @param message The raw message data that should be verified.
 * @param msg_length Length of the message.
 * @param pub_key Public key to use for verification.  The key length will determine the curve to
 * use.
 * @param signature The ECDSA signature for the message data.
 *
 * @return 0 if the message was verified successfully or an error code.
 */
int ecdsa_ecc_hw_verify_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature)
{
	int status;

	if ((ecc_hw == NULL) || (hash == NULL) || (pub_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, hash_algo);
	if (status != 0) {
		return status;
	}

	status = hash->update (hash, message, msg_length);
	if (status != 0) {
		hash->cancel (hash);

		return status;
	}

	return ecdsa_ecc_hw_verify_hash_and_finish (ecc_hw, hash, pub_key, signature);
}

/**
 * Verify a calculated digest against the provided ECDSA signature using an ECC hardware
 * implementation.
 *
 * @param ecc_hw The ECC hardware instance to use for signature verification.
 * @param digest The digest to verify.  This will be zeroized upon return.
 * @param digest_length Length of the digest to verify.
 * @param pub_key Public key to use for verification.  The key length will determine the curve to
 * use.
 * @param signature The ECDSA signature for the digest.
 *
 * @return 0 if the digest was verified successfully or an error code.
 */
static int ecdsa_ecc_hw_verify_digest (const struct ecc_hw *ecc_hw,
	uint8_t digest[HASH_MAX_HASH_LEN], size_t digest_length,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature)
{
	int status;

	status = ecc_hw->ecdsa_verify (ecc_hw, pub_key, signature, digest, digest_length);

	buffer_zeroize (digest, HASH_MAX_HASH_LEN);

	return status;
}

/**
 * Verify an active hash context with an ECDSA signature using an ECC hardware implementation.
 *
 * The hash context will remain active after signature verification, allowing additional updates to
 * be made.  Not all hash implementations support this type of behavior, so it should only be used
 * in scenarios which require it.  Most scenarios should use ecdsa_ecc_hw_verify_hash_and_finish
 * instead.
 *
 * @param ecc_hw The ECC hardware instance to use for signature verification.
 * @param hash The hash engine that contains the active context to verify.
 * @param pub_key Public key to use for verification.  The key length will determine the curve to
 * use.
 * @param signature The ECDSA signature for the hash context.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int ecdsa_ecc_hw_verify_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if ((ecc_hw == NULL) || (hash == NULL) || (pub_key == NULL) || (signature == NULL)) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	status = hash->get_hash (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);

		return status;
	}

	return ecdsa_ecc_hw_verify_digest (ecc_hw, digest, digest_length, pub_key, signature);
}

/**
 * Verify an active hash context with an ECDSA signature using an ECC hardware implementation.
 *
 * The hash context will be finished as part of signature verification.  No additional updates can
 * be made to the hash context, regardless of whether the signature verification was successful or
 * not.
 *
 * @param ecc_hw The ECC hardware instance to use for signature verification.
 * @param hash The hash engine that contains the active context to verify.  The active context will
 * always be terminated upon returning from this call.
 * @param pub_key Public key to use for verification.  The key length will determine the curve to
 * use.
 * @param signature The ECDSA signature for the hash context.
 *
 * @return 0 if the hash was verified successfully or an error code.
 */
int ecdsa_ecc_hw_verify_hash_and_finish (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash, const struct ecc_point_public_key *pub_key,
	const struct ecc_ecdsa_signature *signature)
{
	uint8_t digest[HASH_MAX_HASH_LEN] = {0};
	size_t digest_length;
	int status;

	if (hash == NULL) {
		return ECDSA_INVALID_ARGUMENT;
	}

	digest_length = hash_get_active_hash_length (hash);
	if (digest_length == 0) {
		return ECDSA_NO_ACTVE_HASH;
	}

	if ((ecc_hw == NULL) || (pub_key == NULL) || (signature == NULL)) {
		status = ECDSA_INVALID_ARGUMENT;
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		buffer_zeroize (digest, HASH_MAX_HASH_LEN);
		goto hash_cancel;
	}

	return ecdsa_ecc_hw_verify_digest (ecc_hw, digest, digest_length, pub_key, signature);

hash_cancel:
	hash->cancel (hash);

	return status;
}
