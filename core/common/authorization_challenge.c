// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorization_challenge.h"
#include "common/buffer_util.h"
#include "crypto/rsa.h"


int authorization_challenge_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length)
{
	const struct authorization_challenge *challenge = (const struct authorization_challenge*) auth;
	const uint8_t *token_data = NULL;
	int status;

	if ((challenge == NULL) || (token == NULL) || (length == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&challenge->state->lock);

	if (*token == NULL) {
		/* Generate a new authorization token to challenge the requester. */
		size_t data_length = 0;

		if (challenge->include_tag) {
			token_data = (const uint8_t*) &challenge->token_tag;
			data_length = AUTHORIZATION_CHALLENGE_TAG_LENGTH;
		}

		status = challenge->token->new_token (challenge->token, token_data, data_length, token,
			length);
		if (status == 0) {
			status = AUTHORIZATION_CHALLENGE;
		}
	}
	else {
		/* Verify the authorized data to check for authorization. */
		size_t token_offset;
		size_t aad_length;

		status = challenge->auth_data->get_token_offset (challenge->auth_data, *token, *length,
			&token_offset);
		if (status != 0) {
			goto exit;
		}

		status = challenge->auth_data->get_authenticated_data_length (challenge->auth_data, *token,
			*length, &aad_length);
		if (status != 0) {
			goto exit;
		}

		status = challenge->token->verify_data (challenge->token, *token, *length, token_offset,
			aad_length, challenge->auth_hash);
		if (status == 0) {
			status = challenge->token->invalidate (challenge->token);
		}
		else if (status == AUTH_TOKEN_NOT_VALID) {
			status = AUTHORIZATION_NOT_AUTHORIZED;
		}
	}

exit:
	platform_mutex_unlock (&challenge->state->lock);

	return status;
}

/**
 * Initialize an authorization manager that will generate a challenge to authorize operations.
 *
 * @param auth The authorization manager to initialize.
 * @param state Variable context for authorization.  This must be uninitialized.
 * @param token Token manager to use for authorization tokens.  This must have been initialized to
 * use a nonce of AUTHORIZATION_CHALLENGE_NONCE_LENGTH bytes and no additional data.
 * @param auth_data Parser for the authorized data that will be used when verifying authentication.
 * @param auth_hash Hash algorithm to use for signature verification of authorized tokens.
 *
 * @return 0 if the authorization manager was successfully initialized or an error code.
 */
int authorization_challenge_init (struct authorization_challenge *auth,
	struct authorization_challenge_state *state, const struct auth_token *token,
	const struct authorized_data *auth_data, enum hash_type auth_hash)
{
	if (auth == NULL) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth, 0, sizeof (*auth));

	auth->base.authorize = authorization_challenge_authorize;

	auth->state = state;
	auth->token = token;
	auth->auth_data = auth_data;
	auth->auth_hash = auth_hash;

	return authorization_challenge_init_state (auth);
}

/**
 * Initialize an authorization manager that will generate a challenge to authorize operations.  The
 * challenge token will contain an identifying tag before the nonce.
 *
 * @param auth The authorization manager to initialize.
 * @param state Variable context for authorization.  This must be uninitialized.
 * @param token Token manager to use for authorization tokens.  This must have been initialized to
 * use a nonce of AUTHORIZATION_CHALLENGE_NONCE_LENGTH bytes and an additional
 * AUTHORIZATION_CHALLENGE_TAG_LENGTH bytes of data for the tag.
 * @param auth_data Parser for the authorized data that will be used when verifying authentication.
 * @param auth_hash Hash algorithm to use for signature verification of authorized tokens.
 * @param tag The identifying tag value to include as part of the authorization token.
 *
 * @return 0 if the authorization manager was successfully initialized or an error code.
 */
int authorization_challenge_init_with_tag (struct authorization_challenge *auth,
	struct authorization_challenge_state *state, const struct auth_token *token,
	const struct authorized_data *auth_data, enum hash_type auth_hash, uint32_t tag)
{
	int status;

	status = authorization_challenge_init (auth, state, token, auth_data, auth_hash);
	if (status == 0) {
		auth->token_tag = tag;
		auth->include_tag = true;
	}

	return status;
}

/**
 * Initialize only the variable state of a challenge authorization manager.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param auth The authorization manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int authorization_challenge_init_state (const struct authorization_challenge *auth)
{
	if ((auth == NULL) || (auth->state == NULL) || (auth->token == NULL) ||
		(auth->auth_data == NULL)) {
		return AUTHORIZATION_INVALID_ARGUMENT;
	}

	memset (auth->state, 0, sizeof (*auth->state));

	return platform_mutex_init (&auth->state->lock);
}

/**
 * Release the resources used by an authorization manager.
 *
 * @param auth The authorization manager to release.
 */
void authorization_challenge_release (const struct authorization_challenge *auth)
{
	if (auth != NULL) {
		platform_mutex_free (&auth->state->lock);
	}
}
