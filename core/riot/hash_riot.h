// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_RIOT_H_
#define HASH_RIOT_H_

#include "crypto/hash.h"
#include "reference/include/RiotSha1.h"
#include "reference/include/RiotSha256.h"


/**
 * A riot context for calculating hashes.
 */
struct hash_engine_riot {
	struct hash_engine base;			/**< The base hash engine. */
	union {
#ifdef HASH_ENABLE_SHA1
		RIOT_SHA1_CONTEXT sha1;			/**< Context for SHA1 hashes. */
#endif
		RIOT_SHA256_CONTEXT sha256;		/**< Context for SHA256 hashes. */
	} context;							/**< The hashing contexts. */
	uint8_t active;						/**< The active hash context. */
};


int hash_riot_init (struct hash_engine_riot *engine);
void hash_riot_release (struct hash_engine_riot *engine);


#endif /* HASH_RIOT_H_ */
