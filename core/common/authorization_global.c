// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "authorization_global.h"
#include "common/unused.h"


int authorization_global_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length)
{
	const struct authorization_global *global = (const struct authorization_global*) auth;
	const uint8_t *signature;
	size_t sig_length;
	int status;

	if ((auth == NULL) || (token == NULL) || (length == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	if ((*token == NULL) || (*length == 0)) {
		/* Authorization requires signed data, but no challenge token will be generated. */
		return AUTHORIZATION_NOT_AUTHORIZED;
	}

	status = global->auth_data->get_signature (global->auth_data, *token, *length, &signature,
		&sig_length);
	if (status != 0) {
		return status;
	}

	status = signature_verification_verify_message (global->verification, global->hash,
		global->auth_hash, *token, *length - sig_length, global->authorizing_key,
		global->key_length, signature, sig_length);
	if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
		status = AUTHORIZATION_NOT_AUTHORIZED;
	}

	return status;
}

/**
 * Initialize an authorization manager that uses the same authorized data for all devices.
 *
 * @param auth The global authorization manager to initialize.
 * @param auth_data Authorized data parser used to extract the authorizing signature information.
 * @param hash Hash engine to use for authorized data verification.
 * @param verification Signature verification for the authorized data.
 * @param authorizing_key The authority public key responsible for for authorizing the operation on
 * the device.  This key must be valid for the signature verification context.
 * @param key_length Length of the public key.
 * @param auth_hash Hash algorithm to use for signature verification of the authorized data.
 *
 * @return 0 if the authorization manager was initialized successfully or an error code.
 */
int authorization_global_init (struct authorization_global *auth,
	const struct authorizing_signature *auth_data, const struct hash_engine *hash,
	const struct signature_verification *verification, const uint8_t *authorizing_key,
	size_t key_length, enum hash_type auth_hash)
{
	if (auth == NULL) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (*auth));

	auth->base.authorize = authorization_global_authorize;

	auth->auth_data = auth_data;
	auth->hash = hash;
	auth->verification = verification;
	auth->authorizing_key = authorizing_key;
	auth->key_length = key_length;
	auth->auth_hash = auth_hash;

	return authorization_global_check_init (auth);
}

/**
 * Verify that the authorization manager has been initialized correctly.
 *
 * This is mainly intended for use with statically initialized instances since these checks are
 * naturally part of dynamic initialization.
 *
 * @param auth The global authorization manager to check.
 *
 * @return 0 if the initialization is valid or an error code.
 */
int authorization_global_check_init (const struct authorization_global *auth)
{
	int status;

	if ((auth == NULL) || (auth->auth_data == NULL) || (auth->hash == NULL) ||
		(auth->verification == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	status = auth->verification->is_key_valid (auth->verification, auth->authorizing_key,
		auth->key_length);
	if (status != 0) {
		return status;
	}

	return hash_check_algorithm_is_supported (auth->auth_hash);
}

/**
 * Release the resources used for global authorization.
 *
 * @param auth The global authorization manager to release.
 */
void authorization_global_release (const struct authorization_global *auth)
{
	UNUSED (auth);
}
