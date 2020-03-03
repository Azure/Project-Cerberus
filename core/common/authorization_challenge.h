// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_CHALLENGE_H_
#define AUTHORIZATION_CHALLENGE_H_

#include <stdint.h>
#include <stddef.h>
#include "platform.h"
#include "authorization.h"
#include "common/signature_verification.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/rng.h"


/**
 * Length of the authorization nonce.
 */
#define	AUTH_CHALLENGE_NONCE_LENGTH		32


/**
 * Authorization manager that will generate a challenge for authorization.  Operations without a
 * challenge will not be allowed.
 */
struct authorization_challenge {
	struct authorization base;						/**< Base authorization manager. */
	platform_mutex lock;							/**< Synchronization for authorization requests. */
	struct rng_engine *rng;							/**< Nonce generator. */
	struct hash_engine *hash;						/**< Hash engine for nonce validation. */
	struct ecc_engine *ecc;							/**< ECC engine for challenge signing. */
	struct signature_verification *verification;	/**< Verification for the signed nonce. */
	struct ecc_private_key key;						/**< Challenge signing key. */
	uint8_t *nonce;									/**< Nonce buffer. */
	size_t sig_length;								/**< Maximum length of the nonce signature. */
	size_t nonce_length;							/**< Total length of the nonce. */
};


int authorization_challenge_init (struct authorization_challenge *auth, struct rng_engine *rng,
	struct hash_engine *hash, struct ecc_engine *ecc, const uint8_t *device_key, size_t length,
	struct signature_verification *verification);
void authorization_challenge_release (struct authorization_challenge *auth);


#endif /* AUTHORIZATION_CHALLENGE_H_ */
