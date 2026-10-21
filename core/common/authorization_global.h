// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_GLOBAL_H_
#define AUTHORIZATION_GLOBAL_H_

#include "common/authorization.h"
#include "common/authorizing_signature.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"


/**
 * Authorization that is not specific to any device.  The authorization will globally apply to all
 * devices in any particular category.  No authorization tokens are generated or used.
 */
struct authorization_global {
	struct authorization base;							/**< Base authorization API. */
	const struct authorizing_signature *auth_data;		/**< Parser for the data used for authorization. */
	const struct hash_engine *hash;						/**< Hash engine to use for data verification. */
	const struct signature_verification *verification;	/**< Signature verification for the data. */
	const uint8_t *authorizing_key;						/**< The public key used to verify the data. */
	size_t key_length;									/**< Length of the authorizing public key. */
	enum hash_type auth_hash;							/**< Hash algorithm for signature verification. */
};


int authorization_global_init (struct authorization_global *auth,
	const struct authorizing_signature *auth_data, const struct hash_engine *hash,
	const struct signature_verification *verification, const uint8_t *authorizing_key,
	size_t key_length, enum hash_type auth_hash);
int authorization_global_check_init (const struct authorization_global *auth);
void authorization_global_release (const struct authorization_global *auth);


#endif	/* AUTHORIZATION_GLOBAL_H_ */
