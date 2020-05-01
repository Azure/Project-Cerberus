// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "signature_verification_ecc.h"


static int signature_verification_ecc_verify_signature (struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct signature_verification_ecc *ecc = (struct signature_verification_ecc*) verification;

	if (ecc == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	return ecc->ecc->verify (ecc->ecc, &ecc->key, digest, length, signature, sig_length);
}

/**
 * Initialize ECDSA signature verification.
 *
 * @param verification The verification instance to initialize.
 * @param ecc The ECC engine to use for ECDSA verification.
 * @param key DER encoded ECC key to use with verification.  This can be a public or private key.
 * @param length The length of the ECC key.
 *
 * @return 0 if the verification instance was successfully initialized or an error code.
 */
int signature_verification_ecc_init (struct signature_verification_ecc *verification,
	struct ecc_engine *ecc, const uint8_t *key, size_t length)
{
	int status;

	if ((verification == NULL) || (ecc == NULL) || (key == NULL) || (length == 0)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct signature_verification_ecc));

	status = ecc->init_public_key (ecc, key, length, &verification->key);
	if ((status != 0) && (status != ECC_ENGINE_NOT_EC_KEY)) {
		status = ecc->init_key_pair (ecc, key, length, NULL, &verification->key);
	}
	if (status != 0) {
		return status;
	}

	verification->ecc = ecc;

	verification->base.verify_signature = signature_verification_ecc_verify_signature;

	return 0;
}

/**
 * Release the resources used for ECC signature verification.
 *
 * @param verification The verification instance to release.
 */
void signature_verification_ecc_release (struct signature_verification_ecc *verification)
{
	if (verification) {
		verification->ecc->release_key_pair (verification->ecc, NULL, &verification->key);
	}
}
