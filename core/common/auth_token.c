// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "auth_token.h"
#include "buffer_util.h"


int auth_token_new_token (const struct auth_token *auth, const uint8_t *data, size_t data_length,
	const uint8_t **token, size_t *length)
{
	const struct riot_keys *keys;
	struct ecc_private_key token_key;
	size_t signed_length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int digest_length;
	int sig_length;
	int status;

	if ((auth == NULL) || (token == NULL) || (length == NULL)) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	if ((data != NULL) && (data_length > auth->data_length)) {
		return AUTH_TOKEN_DATA_TOO_LONG;
	}

	/* Invalidate any existing token. */
	auth->state->token_length = 0;

	/* Apply the context-specific data to the token. */
	if (auth->data_length != 0) {
		memset (auth->buffer, 0, auth->data_length);

		if (data != NULL) {
			memcpy (auth->buffer, data, data_length);
		}
	}

	/* Generate a nonce for the token. */
	status = auth->rng->generate_random_buffer (auth->rng, auth->nonce_length,
		&auth->buffer[auth->data_length]);
	if (status != 0) {
		return status;
	}

	signed_length = auth->data_length + auth->nonce_length;

	/* Sign the token. */
	digest_length = hash_calculate (auth->hash, auth->token_hash, auth->buffer, signed_length,
		digest, sizeof (digest));
	if (ROT_IS_ERROR (digest_length)) {
		return digest_length;
	}

	keys = riot_key_manager_get_riot_keys (auth->device_key);

	status = auth->ecc->init_key_pair (auth->ecc, keys->alias_key, keys->alias_key_length,
		&token_key, NULL);
	if (status != 0) {
		goto release_riot;
	}

	sig_length = auth->ecc->sign (auth->ecc, &token_key, digest, digest_length,
		&auth->buffer[signed_length], auth->sig_length);
	if (ROT_IS_ERROR (sig_length)) {
		status = sig_length;
		goto release_key;
	}

	if (auth->validity_time != 0) {
		status = platform_init_timeout (auth->validity_time, &auth->state->expiration);
		if (status != 0) {
			goto release_key;
		}
	}

	auth->state->token_length = signed_length + sig_length;

	*token = auth->buffer;
	*length = auth->state->token_length;

release_key:
	auth->ecc->release_key_pair (auth->ecc, &token_key, NULL);
release_riot:
	riot_key_manager_release_riot_keys (auth->device_key, keys);

	return status;
}

int auth_token_verify_data (const struct auth_token *auth, const uint8_t *authorized, size_t length,
	size_t token_offset, size_t aad_length, enum hash_type sig_hash)
{
	size_t auth_length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	int digest_length;
	int status;

	if ((auth == NULL) || (authorized == NULL)) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	auth_length = token_offset + auth->state->token_length + aad_length;

	/* No need to check the provided data if any precondition is not met:
	 * - There must be an active token.
	 * - The signed data needs to contain the token, so it must be longer than the token itself.
	 * - If there is any AAD included, the data must be longer than the combined length of the token
	 *   and the AAD.
	 * - If the token exists at an offset in the authorized data, the data must be long enough to
	 *   account for this offset.
	 * - The active token must not be expired. */
	if ((auth->state->token_length != 0) && (auth->state->token_length < length) &&
		(token_offset < length) && (aad_length < length) && (length > auth_length)) {
		if (auth->validity_time != 0) {
			status = platform_has_timeout_expired (&auth->state->expiration);
			if (status == 1) {
				return AUTH_TOKEN_NOT_VALID;
			}
			else if (status != 0) {
				return status;
			}
		}

		/* Before spending time on signature verification, ensure the authorization token in the
		 * data is correct. */
		status = buffer_compare (&authorized[token_offset], auth->buffer,
			auth->state->token_length);
		if (status != 0) {
			return AUTH_TOKEN_NOT_VALID;
		}

		digest_length = hash_calculate (auth->hash, sig_hash, authorized, auth_length, digest,
			sizeof (digest));
		if (ROT_IS_ERROR (digest_length)) {
			return digest_length;
		}

		/* Load the authorization key fresh each time to ensure a clean verification state. */
		status = auth->authority->set_verification_key (auth->authority, auth->authority_key,
			auth->auth_key_length);
		if (status != 0) {
			return status;
		}

		status = auth->authority->verify_signature (auth->authority, digest, digest_length,
			&authorized[auth_length], length - auth_length);
		if (status == SIG_VERIFICATION_BAD_SIGNATURE) {
			/* If the signature is not correct, report the data as invalid.  If there is some other
			 * type of failure during verification, report that error. */
			status = AUTH_TOKEN_NOT_VALID;
		}
	}
	else {
		status = AUTH_TOKEN_NOT_VALID;
	}

	return status;
}

int auth_token_invalidate (const struct auth_token *auth)
{
	if (auth == NULL) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	auth->state->token_length = 0;

	return 0;
}

/**
 * Determine the maximum signature length that will needed for token signing.
 *
 * @param auth The token handler to query.
 *
 * @return The maximum signature length or an error code.
 */
static int auth_token_get_max_signature_length (const struct auth_token *auth)
{
	const struct riot_keys *keys;
	struct ecc_private_key token_key;
	int status;

	keys = riot_key_manager_get_riot_keys (auth->device_key);

	status = auth->ecc->init_key_pair (auth->ecc, keys->alias_key, keys->alias_key_length,
		&token_key, NULL);
	if (status != 0) {
		goto release_riot;
	}

	status = auth->ecc->get_signature_max_length (auth->ecc, &token_key);
	if (ROT_IS_ERROR (status)) {
		goto release_key;
	}

release_key:
	auth->ecc->release_key_pair (auth->ecc, &token_key, NULL);
release_riot:
	riot_key_manager_release_riot_keys (auth->device_key, keys);

	return status;
}

/**
 * Initialize the base structure and API.
 *
 * @param auth The authorization token handler to initialize.
 * @param state Variable context for the token handler.  This must be uninitialized.
 * @param rng The RNG engine to use for token nonce generation.
 * @param hash The hash engine to use for token digests.
 * @param ecc The ECC engine to use for token signing.
 * @param device_key Manager for the device key that will be used to sign the authorization token.
 * @param authority_key The public key for entity that will be authorizing tokens.
 * @param key_length Length of the authority public key.
 * @param authority Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param data_length Length of any optional, context-specific data that will be added during token
 * creation.
 * @param nonce_length Length of the random nonce that should be added to the token.  This will
 * be appended to the context data, if any is provided.
 * @param sig_hash The hash algorithm to use when generating the token signature.
 * @param validity_time The amount of time, in milliseconds, that a token will remain valid.  If a
 * token never expires, set this to 0.
 *
 * @return 0 if the base API was initialized successfully or an error code.
 */
static int auth_token_init_api (struct auth_token *auth, struct auth_token_state *state,
	struct rng_engine *rng, struct hash_engine *hash, struct ecc_engine *ecc,
	struct riot_key_manager *device_key, const uint8_t *authority_key, size_t key_length,
	const struct signature_verification *authority, size_t data_length, size_t nonce_length,
	enum hash_type sig_hash, uint32_t validity_time)
{
	int status;

	if ((auth == NULL) || (state == NULL) || (rng == NULL) || (hash == NULL) || (ecc == NULL) ||
		(device_key == NULL) || (authority_key == NULL) || (key_length == 0) ||
		(authority == NULL) || (nonce_length == 0)) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (struct auth_token));

	auth->new_token = auth_token_new_token;
	auth->verify_data = auth_token_verify_data;
	auth->invalidate = auth_token_invalidate;

	auth->state = state;
	auth->rng = rng;
	auth->hash = hash;
	auth->ecc = ecc;
	auth->device_key = device_key;
	auth->authority = authority;
	auth->authority_key = authority_key;
	auth->auth_key_length = key_length;
	auth->data_length = data_length;
	auth->nonce_length = nonce_length;
	auth->token_hash = sig_hash;
	auth->validity_time = validity_time;

	status = auth_token_get_max_signature_length (auth);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	auth->sig_length = status;

	return 0;
}

/**
 * Initialize the token state and allocate the dynamic token buffer.
 *
 * @param auth The token handler to initialize.
 *
 * @return 0 if the state was initialized successfully or an error code.
 */
static int auth_token_allocate_dynamic_state (struct auth_token *auth)
{
	memset (auth->state, 0, sizeof (struct auth_token_state));

	auth->buffer = platform_malloc (auth->buffer_length);
	if (auth->buffer == NULL) {
		return AUTH_TOKEN_NO_MEMORY;
	}

	return 0;
}

/**
 * Initialize the token state and verify the static token buffer.
 *
 * @param auth The token handler to initialize.
 *
 * @return 0 if the state was initialized successfully or an error code.
 */
static int auth_token_validate_static_state (const struct auth_token *auth)
{
	memset (auth->state, 0, sizeof (struct auth_token_state));

	if (auth->buffer_length < (auth->data_length + auth->nonce_length + auth->sig_length)) {
		return AUTH_TOKEN_SMALL_BUFFER;
	}

	return 0;
}

/**
 * Initialize a handler for a single authorization token.  The buffer used to maintain the valid
 * token will be dynamically allocated.
 *
 * @param auth The authorization token handler to initialize.
 * @param state Variable context for the token handler.  This must be uninitialized.
 * @param rng The RNG engine to use for token nonce generation.
 * @param hash The hash engine to use for token digests.
 * @param ecc The ECC engine to use for token signing.
 * @param device_key Manager for the device key that will be used to sign the authorization token.
 * @param authority_key The public key for entity that will be authorizing tokens.
 * @param key_length Length of the authority public key.
 * @param authority Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param data_length Length of any optional, context-specific data that will be added during token
 * creation.
 * @param nonce_length Length of the random nonce that should be added to the token.  This will
 * be appended to the context data, if any is provided.
 * @param sig_hash The hash algorithm to use when generating the token signature.
 * @param validity_time The amount of time, in milliseconds, that a token will remain valid.  If a
 * token never expires, set this to 0.
 *
 * @return 0 if the token handler was initialized successfully or an error code.
 */
int auth_token_init (struct auth_token *auth, struct auth_token_state *state,
	struct rng_engine *rng, struct hash_engine *hash, struct ecc_engine *ecc,
	struct riot_key_manager *device_key, const uint8_t *authority_key, size_t key_length,
	const struct signature_verification *authority, size_t data_length, size_t nonce_length,
	enum hash_type sig_hash, uint32_t validity_time)
{
	int status;

	status = auth_token_init_api (auth, state, rng, hash, ecc, device_key, authority_key,
		key_length, authority, data_length, nonce_length, sig_hash, validity_time);
	if (status != 0) {
		return status;
	}

	auth->buffer_length = auth->data_length + auth->nonce_length + auth->sig_length;
	auth->alloc_buffer = true;

	return auth_token_allocate_dynamic_state (auth);
}

/**
 * Initialize a handler for a single authorization token.  The buffer used to maintain the valid
 * token is managed by the caller.
 *
 * @param auth The authorization token handler to initialize.
 * @param state Variable context for the token handler.  This must be uninitialized.
 * @param rng The RNG engine to use for token nonce generation.
 * @param hash The hash engine to use for token digests.
 * @param ecc The ECC engine to use for token signing.
 * @param device_key Manager for the device key that will be used to sign the authorization token.
 * @param authority_key The public key for entity that will be authorizing tokens.
 * @param key_length Length of the authority public key.
 * @param authority Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param data_length Length of any optional, context-specific data that will be added during token
 * creation.
 * @param nonce_length Length of the random nonce that should be added to the token.  This will
 * be appended to the context data, if any is provided.
 * @param sig_hash The hash algorithm to use when generating the token signature.
 * @param validity_time The amount of time, in milliseconds, that a token will remain valid.  If a
 * token never expires, set this to 0.
 * @param token_buffer The buffer to use for token management.
 * @param buffer_length Length of the token buffer.
 *
 * @return 0 if the token handler was initialized successfully or an error code.
 */
int auth_token_init_with_buffer (struct auth_token *auth, struct auth_token_state *state,
	struct rng_engine *rng, struct hash_engine *hash, struct ecc_engine *ecc,
	struct riot_key_manager *device_key, const uint8_t *authority_key, size_t key_length,
	const struct signature_verification *authority, size_t data_length, size_t nonce_length,
	enum hash_type sig_hash, uint32_t validity_time, uint8_t *token_buffer, size_t buffer_length)
{
	int status;

	if (token_buffer == NULL) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	status = auth_token_init_api (auth, state, rng, hash, ecc, device_key, authority_key,
		key_length, authority, data_length, nonce_length, sig_hash, validity_time);
	if (status != 0) {
		return status;
	}

	auth->buffer = token_buffer;
	auth->buffer_length = buffer_length;

	return auth_token_validate_static_state (auth);
}

/**
 * Initialize the variable state for an authorization token handler and allocate the token buffer.
 * The rest of the token handler is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance, but it cannot be used with a
 * constant instance due to the dynamic buffer allocation.
 *
 * @param auth The authorization token handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int auth_token_init_dynamic_state (struct auth_token *auth)
{
	int status;

	if ((auth == NULL) || (auth->state == NULL) || (auth->rng == NULL) || (auth->hash == NULL) ||
		(auth->ecc == NULL) || (auth->device_key == NULL) || (auth->authority_key == NULL) ||
		(auth->auth_key_length == 0) || (auth->authority == NULL) || (auth->nonce_length == 0)) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	status = auth_token_get_max_signature_length (auth);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if ((size_t) status != auth->sig_length) {
		return AUTH_TOKEN_WRONG_SIG_LENGTH;
	}

	return auth_token_allocate_dynamic_state (auth);
}

/**
 * Initialize only the variable state for an authorization token handler.  The rest of the token
 * handler is assumed to have already been initialized, including the token buffer, which would need
 * to be externally managed.
 *
 * This would generally be used with a statically initialized instance and can support constant
 * instances.
 *
 * @param auth The authorization token handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int auth_token_init_state (const struct auth_token *auth)
{
	int status;

	if ((auth == NULL) || (auth->state == NULL) || (auth->rng == NULL) || (auth->hash == NULL) ||
		(auth->ecc == NULL) || (auth->device_key == NULL) || (auth->authority_key == NULL) ||
		(auth->auth_key_length == 0) || (auth->authority == NULL) || (auth->nonce_length == 0) ||
		(auth->buffer == NULL)) {
		return AUTH_TOKEN_INVALID_ARGUMENT;
	}

	status = auth_token_get_max_signature_length (auth);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if ((size_t) status != auth->sig_length) {
		return AUTH_TOKEN_WRONG_SIG_LENGTH;
	}

	return auth_token_validate_static_state (auth);
}

/**
 * Release the resources used for authorization token management.
 *
 * @param auth The token handler to release.
 */
void auth_token_release (const struct auth_token *auth)
{
	if ((auth != NULL) && auth->alloc_buffer) {
		platform_free (auth->buffer);
	}
}
