// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "signature_verification_ecc.h"
#include "asn1/ecc_der_util.h"


int signature_verification_ecc_verify_signature (const struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	const struct signature_verification_ecc *ecdsa =
		(const struct signature_verification_ecc*) verification;
	int status;

	if (ecdsa == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	if (!ecdsa->state->key_valid) {
		return SIG_VERIFICATION_NO_KEY;
	}

	status = ecdsa->ecc->verify (ecdsa->ecc, &ecdsa->state->key, digest, length, signature,
		sig_length);
	if (status == ECC_ENGINE_BAD_SIGNATURE) {
		return SIG_VERIFICATION_BAD_SIGNATURE;
	}
	else {
		return status;
	}
}

int signature_verification_ecc_get_max_signature_length (
	const struct signature_verification *verification, size_t *max_length)
{
	const struct signature_verification_ecc *ecdsa =
		(const struct signature_verification_ecc*) verification;
	int status;

	if ((ecdsa == NULL) || (max_length == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	if (ecdsa->state->key_valid) {
		status = ecdsa->ecc->get_signature_max_verify_length (ecdsa->ecc, &ecdsa->state->key);
	}
	else {
		status = ECC_DER_ECDSA_MAX_LENGTH;
	}

	if (!ROT_IS_ERROR (status)) {
		*max_length = status;
		status = 0;
	}

	return status;
}

/**
 * Load an ECC public key using the verification ECC engine.
 *
 * @param ecdsa The verification context to use when loading the key.
 * @param key The DER encoded key to load.  This can represent either a public or private key.
 * @param length Length of the key.
 * @param pub_key Output for the public key loaded by the ECC engine.
 *
 * @return 0 if the key was loaded successfully or an error code.
 */
static int signature_verification_ecc_load_key (const struct signature_verification_ecc *ecdsa,
	const uint8_t *key, size_t length, struct ecc_public_key *pub_key)
{
	int status;

	status = ecdsa->ecc->init_public_key (ecdsa->ecc, key, length, pub_key);
	if ((status != 0) && (status != ECC_ENGINE_NOT_EC_KEY)) {
		status = ecdsa->ecc->init_key_pair (ecdsa->ecc, key, length, NULL, pub_key);
	}

	if (status != 0) {
		if (status == ECC_ENGINE_NOT_EC_KEY) {
			return SIG_VERIFICATION_INVALID_KEY;
		}
		else {
			return status;
		}
	}

	return status;
}

int signature_verification_ecc_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length)
{
	const struct signature_verification_ecc *ecdsa =
		(const struct signature_verification_ecc*) verification;
	int status = 0;

	if (ecdsa == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	if ((key != NULL) && (length == 0)) {
		return SIG_VERIFICATION_INCONSISTENT_KEY;
	}

	if (ecdsa->state->key_valid) {
		ecdsa->ecc->release_key_pair (ecdsa->ecc, NULL, &ecdsa->state->key);
		ecdsa->state->key_valid = false;
	}

	if (key != NULL) {
		status = signature_verification_ecc_load_key (ecdsa, key, length, &ecdsa->state->key);
		if (status == 0) {
			ecdsa->state->key_valid = true;
		}
	}

	return status;
}

int signature_verification_ecc_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length)
{
	const struct signature_verification_ecc *ecdsa =
		(const struct signature_verification_ecc*) verification;
	struct ecc_public_key pub_key;
	int status;

	if ((ecdsa == NULL) || (key == NULL) || (length == 0)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	status = signature_verification_ecc_load_key (ecdsa, key, length, &pub_key);
	if (status == 0) {
		ecdsa->ecc->release_key_pair (ecdsa->ecc, NULL, &pub_key);
	}

	return status;
}

/**
 * Initialize ECDSA signature verification.
 *
 * @param verification The verification instance to initialize.
 * @param state Variable context for verification.  This must be uninitialized.
 * @param ecc The ECC engine to use for ECDSA verification.
 * @param key An optional key to use for verification operations.  If provided, this must be a DER
 * encoded ECC public or private key.  Set this to null if no key should be configured.
 * @param length The length of the ECC key, if one is provided.  This argument is ignored if the key
 * is null.
 *
 * @return 0 if the verification instance was successfully initialized or an error code.
 */
int signature_verification_ecc_init (struct signature_verification_ecc *verification,
	struct signature_verification_ecc_state *state, const struct ecc_engine *ecc,
	const uint8_t *key,	size_t length)
{
	int status;

	status = signature_verification_ecc_init_api (verification, state, ecc);
	if (status != 0) {
		return status;
	}

	return signature_verification_ecc_init_state (verification, key, length);
}

/**
 * Initialize the API and static contents of an ECDSA signature verification instance.  The result
 * of the call is the same as static initialization, except parameter validation is performed.
 *
 * Instances that have only had the API initialized do not need to be released.
 *
 * @param verification The verification instance to initialize.
 * @param state Variable context for verification.  This must be uninitialized.
 * @param ecc The ECC engine to use for ECDSA verification.
 *
 * @return 0 if the verification instance was initialized successfully or
 * SIG_VERIFICATION_INVALID_ARGUMENT if there are null parameters.
 */
int signature_verification_ecc_init_api (struct signature_verification_ecc *verification,
	struct signature_verification_ecc_state *state, const struct ecc_engine *ecc)
{
	if ((verification == NULL) || (state == NULL) || (ecc == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct signature_verification_ecc));

	verification->base.verify_signature = signature_verification_ecc_verify_signature;
	verification->base.get_max_signature_length =
		signature_verification_ecc_get_max_signature_length;
	verification->base.set_verification_key = signature_verification_ecc_set_verification_key;
	verification->base.is_key_valid = signature_verification_ecc_is_key_valid;

	verification->ecc = ecc;
	verification->state = state;
	verification->state->key_valid = false;

	return 0;
}

/**
 * Initialize only the variable state for ECDSA signature verification.  The rest of the
 * verification instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param verification The verification instance that contains the state to initialize.
 * @param key An optional key to use for verification operations.  If provided, this must be a DER
 * encoded ECC public or private key.  Set this to null if no key should be configured.
 * @param length The length of the ECC key, if one is provided.  This argument is ignored if the key
 * is null.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int signature_verification_ecc_init_state (const struct signature_verification_ecc *verification,
	const uint8_t *key, size_t length)
{
	if ((verification == NULL) || (verification->state == NULL) || (verification->ecc == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification->state, 0, sizeof (struct signature_verification_ecc_state));

	return signature_verification_ecc_set_verification_key (&verification->base, key, length);
}

/**
 * Release the resources used for ECC signature verification.
 *
 * @param verification The verification instance to release.
 */
void signature_verification_ecc_release (const struct signature_verification_ecc *verification)
{
	if (verification && verification->state->key_valid) {
		verification->ecc->release_key_pair (verification->ecc, NULL, &verification->state->key);
	}
}
