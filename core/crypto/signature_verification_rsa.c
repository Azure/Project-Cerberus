// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "signature_verification_rsa.h"
#include "common/unused.h"


int signature_verification_rsa_verify_signature (const struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	const struct signature_verification_rsa *rsa =
		(const struct signature_verification_rsa*) verification;
	int status;

	if (rsa == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	if (rsa->state->key == NULL) {
		return SIG_VERIFICATION_NO_KEY;
	}

	status = rsa->rsa->sig_verify (rsa->rsa, rsa->state->key, signature, sig_length,
		HASH_TYPE_SHA256, digest, length);
	if (status == RSA_ENGINE_BAD_SIGNATURE) {
		return SIG_VERIFICATION_BAD_SIGNATURE;
	}
	else {
		return status;
	}
}

int signature_verification_rsa_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length)
{
	const struct signature_verification_rsa *rsa =
		(const struct signature_verification_rsa*) verification;

	if (rsa == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	/* The key needs to be an rsa_public_key.  Assume it is correct if the length matches. */
	if ((key != NULL) && (length != sizeof (struct rsa_public_key))) {
		return SIG_VERIFICATION_INVALID_KEY;
	}

	rsa->state->key = (const struct rsa_public_key*) key;

	return 0;
}

int signature_verification_rsa_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length)
{
	if ((verification == NULL) || (key == NULL) || (length == 0)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	if (length == sizeof (struct rsa_public_key)) {
		return 0;
	}
	else {
		return SIG_VERIFICATION_INVALID_KEY;
	}
}

/**
 * Initialize RSA public key signature verification.
 *
 * @param verification The verification instance to initialize.
 * @param state Variable context for verification.  This must be uninitialized.
 * @param rsa The RSA engine to use for verification.
 * @param key An optional RSA public key to use for signature verification.  Set this to null if no
 * key should be configured.
 *
 * @return 0 if the verification instance was successfully initialized or an error code.
 */
int signature_verification_rsa_init (struct signature_verification_rsa *verification,
	struct signature_verification_rsa_state *state, struct rsa_engine *rsa,
	const struct rsa_public_key *key)
{
	int status;

	status = signature_verification_rsa_init_api (verification, state, rsa);
	if (status != 0) {
		return status;
	}

	return signature_verification_rsa_init_state (verification, key);
}

/**
 * Initialize the API and static contents of an RSA signature verification instance.  The result
 * of the call is the same as static initialization, except parameter validation is performed.
 *
 * Instances that have only had the API initialized do not need to be released.
 *
 * @param verification The verification instance to initialize.
 * @param state Variable context for verification.  This must be uninitialized.
 * @param rsa The RSA engine to use for verification.
 *
 * @return 0 if the verification instance was initialized successfully or
 * SIG_VERIFICATION_INVALID_ARGUMENT if there are null parameters.
 */
int signature_verification_rsa_init_api (struct signature_verification_rsa *verification,
	struct signature_verification_rsa_state *state, struct rsa_engine *rsa)
{
	if ((verification == NULL) || (state == NULL) || (rsa == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct signature_verification_rsa));

	verification->base.verify_signature = signature_verification_rsa_verify_signature;
	verification->base.set_verification_key = signature_verification_rsa_set_verification_key;
	verification->base.is_key_valid = signature_verification_rsa_is_key_valid;

	verification->rsa = rsa;
	verification->state = state;

	return 0;
}

/**
 * Initialize only the variable state for RSA signature verification.  The rest of the verification
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param verification The verification instance that contains the state to initialize.
 * @param key An optional RSA public key to use for signature verification.  Set this to null if no
 * key should be configured.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int signature_verification_rsa_init_state (const struct signature_verification_rsa *verification,
	const struct rsa_public_key *key)
{
	if ((verification == NULL) || (verification->state == NULL) || (verification->rsa == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification->state, 0, sizeof (struct signature_verification_rsa_state));

	verification->state->key = key;

	return 0;
}

/**
 * Release the resources used for RSA signature verification.
 *
 * @param verification The verification instance to release.
 */
void signature_verification_rsa_release (const struct signature_verification_rsa *verification)
{
	UNUSED (verification);
}
