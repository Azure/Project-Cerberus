// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_CHALLENGE_H_
#define AUTHORIZATION_CHALLENGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "auth_token.h"
#include "authorization.h"
#include "authorized_data.h"
#include "platform_api.h"
#include "crypto/hash.h"


/**
 * Length of the authorization nonce.
 */
#define	AUTHORIZATION_CHALLENGE_NONCE_LENGTH		32

/**
 * Length of additional tag data length, if configured to include one.
 */
#define	AUTHORIZATION_CHALLENGE_TAG_LENGTH			sizeof (uint32_t)


/**
 * Variable context for challenged-based authorization.
 */
struct authorization_challenge_state {
	platform_mutex lock;	/**< Synchronization for authorization requests. */
};

/**
 * Authorization manager that will generate a challenge for authorization.  Operations without a
 * signed challenge will not be allowed.
 */
struct authorization_challenge {
	struct authorization base;						/**< Base authorization manager. */
	struct authorization_challenge_state *state;	/**< Variable context for authorization. */
	const struct auth_token *token;					/**< Authorization token handler. */
	const struct authorized_data *auth_data;		/**< Authorized data handler. */
	uint32_t token_tag;								/**< Additional data to add to generated tokens. */
	bool include_tag;								/**< Flag to indicate if the tag should be added. */
	enum hash_type auth_hash;						/**< Hash algorithm to use for token verification. */
};


int authorization_challenge_init (struct authorization_challenge *auth,
	struct authorization_challenge_state *state, const struct auth_token *token,
	const struct authorized_data *auth_data, enum hash_type auth_hash);
int authorization_challenge_init_with_tag (struct authorization_challenge *auth,
	struct authorization_challenge_state *state, const struct auth_token *token,
	const struct authorized_data *auth_data, enum hash_type auth_hash, uint32_t tag);
int authorization_challenge_init_state (const struct authorization_challenge *auth);
void authorization_challenge_release (const struct authorization_challenge *auth);


#endif	/* AUTHORIZATION_CHALLENGE_H_ */
