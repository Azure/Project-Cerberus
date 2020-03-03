// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "signature_verification_rsa.h"


static int signature_verification_rsa_verify_signature (struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_rsa *rsa = (struct signature_verification_rsa*) verification;

	if (rsa == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	return rsa->rsa->sig_verify (rsa->rsa, rsa->key, signature, sig_length, digest, length);
}

/**
 * Initialize signature verification with an RSA public key.
 *
 * @param verification The verification instance to initialize.
 * @param rsa The RSA engine to use for verification.
 * @param key The RSA public key for the signatures to verify.
 *
 * @return 0 if the verification instance was successfully initialized or an error code.
 */
int signature_verification_rsa_init (struct signature_verification_rsa *verification,
	struct rsa_engine *rsa, const struct rsa_public_key *key)
{
	if ((verification == NULL) || (rsa == NULL) || (key == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct signature_verification_rsa));

	verification->rsa = rsa;
	verification->key = key;

	verification->base.verify_signature = signature_verification_rsa_verify_signature;

	return 0;
}

/**
 * Release the resources used for RSA signature verification.
 *
 * @param verification The verification instance to release.
 */
void signature_verification_rsa_release (struct signature_verification_rsa *verification)
{

}
