// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_CHALLENGE_STATIC_H_
#define AUTHORIZATION_CHALLENGE_STATIC_H_

#include "authorization_challenge.h"


/* Internal functions declared to allow for static initialization. */
int authorization_challenge_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length);


/**
 * Constant initializer for the authorization API.
 */
#define	AUTHORIZATION_CHALLENGE_API_INIT  { \
		.authorize = authorization_challenge_authorize, \
	}

/**
 * Initialize a static authorization manager that will generate a challenge to authorize operations.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for authorization.
 * @param token_ptr Token manager to use for authorization tokens.  This must have been initialized
 * to use a nonce of AUTHORIZATION_CHALLENGE_NONCE_LENGTH bytes and no additional data.
 * @param auth_data_ptr Parser for the authorized data that will be used when verifying
 * authentication.
 * @param auth_hash_arg Hash algorithm to use for signature verification of authorized tokens.
 */
#define	authorization_challenge_static_init(state_ptr, token_ptr, auth_data_ptr, auth_hash_arg) { \
		.base = AUTHORIZATION_CHALLENGE_API_INIT, \
		.state = state_ptr, \
		.token = token_ptr, \
		.auth_data = auth_data_ptr, \
		.include_tag = false, \
		.auth_hash = auth_hash_arg, \
	}

/**
 * Initialize a static authorization manager that will generate a challenge to authorize operations.
 * The challenge token will contain an identifying tag before the nonce.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for authorization.  This must be uninitialized.
 * @param token_ptr Token manager to use for authorization tokens.  This must have been initialized
 * to use a nonce of AUTHORIZATION_CHALLENGE_NONCE_LENGTH bytes and an additional 4 bytes of data
 * for the uint32_t tag.
 * @param auth_data_ptr Parser for the authorized data that will be used when verifying
 * authentication.
 * @param auth_hash_arg Hash algorithm to use for signature verification of authorized tokens.
 * @param tag_arg The identifying tag value to include as part of the authorization token.
 */
#define	authorization_challenge_static_init_with_tag(state_ptr, token_ptr, auth_data_ptr, \
	auth_hash_arg, tag_arg) { \
		.base = AUTHORIZATION_CHALLENGE_API_INIT, \
		.state = state_ptr, \
		.token = token_ptr, \
		.auth_data = auth_data_ptr, \
		.token_tag = tag_arg, \
		.include_tag = true, \
		.auth_hash = auth_hash_arg, \
	}


#endif	/* AUTHORIZATION_CHALLENGE_STATIC_H_ */
