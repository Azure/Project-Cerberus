// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "authorization_challenge.h"
#include "crypto/rsa.h"


static int authorization_challenge_authorize (struct authorization *auth, uint8_t **nonce,
	size_t *length)
{
	struct authorization_challenge *challenge = (struct authorization_challenge*) auth;
	uint8_t hash[SHA256_HASH_LENGTH];
	int status;

	if ((challenge == NULL) || (nonce == NULL) || (length == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&challenge->lock);

	if (*nonce == NULL) {
		challenge->nonce_length = 0;

		status = challenge->rng->generate_random_buffer (challenge->rng,
			AUTH_CHALLENGE_NONCE_LENGTH, challenge->nonce);
		if (status != 0) {
			goto exit;
		}

		status = challenge->hash->calculate_sha256 (challenge->hash, challenge->nonce,
			AUTH_CHALLENGE_NONCE_LENGTH, hash, sizeof (hash));
		if (status != 0) {
			goto exit;
		}

		status = challenge->ecc->sign (challenge->ecc, &challenge->key, hash, SHA256_HASH_LENGTH,
			challenge->nonce + AUTH_CHALLENGE_NONCE_LENGTH, challenge->sig_length);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		challenge->nonce_length = AUTH_CHALLENGE_NONCE_LENGTH + status;

		*nonce = challenge->nonce;
		*length = challenge->nonce_length;
		status = AUTHORIZATION_CHALLENGE;
	}
	else if ((challenge->nonce_length != 0) && (*length > challenge->nonce_length)) {
		status = challenge->hash->calculate_sha256 (challenge->hash, *nonce,
			challenge->nonce_length, hash, sizeof (hash));
		if (status != 0) {
			goto exit;
		}

		status = challenge->verification->verify_signature (challenge->verification, hash,
			SHA256_HASH_LENGTH, (*nonce) + challenge->nonce_length,
			*length - challenge->nonce_length);
		if (status == 0) {
			if (memcmp (*nonce, challenge->nonce, challenge->nonce_length) == 0) {
				challenge->nonce_length = 0;
			}
			else {
				status = AUTHORIZATION_NOT_AUTHORIZED;
			}
		}
		else if ((status == RSA_ENGINE_BAD_SIGNATURE) || (status == ECC_ENGINE_BAD_SIGNATURE)) {
			status = AUTHORIZATION_NOT_AUTHORIZED;
		}
	}
	else {
		status = AUTHORIZATION_NOT_AUTHORIZED;
	}

exit:
	platform_mutex_unlock (&challenge->lock);
	return status;
}

/**
 * Initialized an authorization manager that will generate a challenge to authorize operations.
 *
 * @param auth The authorization manager to initialize.
 * @param rng Random number generator to use for generating authorization nonces.
 * @param hash The hash engine to use for nonce validation.
 * @param ecc The ECC engine to use for signing authorization challenges.
 * @param device_key DER encoded device-specific ECC key for signing authorization challenges.
 * @param length Length of the device-specific key.
 * @param verification Signature verification for authorization responses.
 *
 * @return 0 if the authorization manager was successfully initialized or an error code.
 */
int authorization_challenge_init (struct authorization_challenge *auth, struct rng_engine *rng,
	struct hash_engine *hash, struct ecc_engine *ecc, const uint8_t *device_key, size_t length,
	struct signature_verification *verification)
{
	int status;

	if ((auth == NULL) || (rng == NULL) || (hash == NULL) || (ecc == NULL) ||
		(device_key == NULL) || (verification == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct authorization_challenge));

	status = platform_mutex_init (&auth->lock);
	if (status != 0) {
		return status;
	}

	status = ecc->init_key_pair (ecc, device_key, length, &auth->key, NULL);
	if (status != 0) {
		goto exit_lock;
	}

	status = ecc->get_signature_max_length (ecc, &auth->key);
	if (ROT_IS_ERROR (status)) {
		goto exit_key;
	}

	auth->sig_length = status;
	auth->nonce = platform_malloc (AUTH_CHALLENGE_NONCE_LENGTH + auth->sig_length);
	if (auth->nonce == NULL) {
		status = AUTHORIZATION_NO_MEMORY;
		goto exit_key;
	}

	auth->base.authorize = authorization_challenge_authorize;

	auth->rng = rng;
	auth->hash = hash;
	auth->ecc = ecc;
	auth->verification = verification;

	return 0;

exit_key:
	ecc->release_key_pair (ecc, &auth->key, NULL);
exit_lock:
	platform_mutex_free (&auth->lock);
	return status;
}

/**
 * Release the resources used by an authorization manager.
 *
 * @param auth The authorization manager to release.
 */
void authorization_challenge_release (struct authorization_challenge *auth)
{
	if (auth != NULL) {
		platform_mutex_free (&auth->lock);
		auth->ecc->release_key_pair (auth->ecc, &auth->key, NULL);
		platform_free (auth->nonce);
	}
}
