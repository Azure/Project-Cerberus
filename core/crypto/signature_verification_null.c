// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"
#include "signature_verification_null.h"
#include "common/unused.h"


int signature_verification_null_verify_signature (
	const struct signature_verification *verification, const uint8_t *digest, size_t length,
	const uint8_t *signature, size_t sig_length)
{
	UNUSED (length);
	UNUSED (sig_length);

	if ((verification == NULL) || (digest == NULL) || (signature == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	return 0;
}

int signature_verification_null_get_max_signature_length (
	const struct signature_verification *verification, size_t *max_length)
{
	if ((verification == NULL) || (max_length == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	*max_length = RSA_MAX_KEY_LENGTH;

	return 0;
}

int signature_verification_null_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length)
{
	UNUSED (length);
	UNUSED (key);

	if (verification == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	return 0;
}

int signature_verification_null_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length)
{
	UNUSED (length);

	if ((verification == NULL) || (key == NULL)) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	return 0;
}

/**
 * Initialize a null signature verification instance and its API.
 *
 * @param verification The verification instance to initialize.
 *
 * @return 0 if the verification instance was successfully initialized or an error code.
 */
int signature_verification_null_init (struct signature_verification_null *verification)
{
	if (verification == NULL) {
		return SIG_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct signature_verification_null));

	verification->base.verify_signature = signature_verification_null_verify_signature;
	verification->base.get_max_signature_length =
		signature_verification_null_get_max_signature_length;
	verification->base.set_verification_key = signature_verification_null_set_verification_key;
	verification->base.is_key_valid = signature_verification_null_is_key_valid;

	return 0;
}

/**
 * Release the resources used for null signature verification.
 *
 * @param verification The verification instance to release.
 */
void signature_verification_null_release (const struct signature_verification_null *verification)
{
	UNUSED (verification);
}
