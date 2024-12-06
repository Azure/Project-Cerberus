// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_OPENSSL_H_
#define HASH_OPENSSL_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include "crypto/hash.h"


/**
 * Variable context for hashing with OpenSSL.
 */
struct hash_engine_openssl_state {
	EVP_MD_CTX *sha;			/**< The context for calculating incremental hashes. */
	int active;					/**< The type of initialized context. */
};

/**
 * An OpenSSL context for calculating hashes.
 */
struct hash_engine_openssl {
	struct hash_engine base;					/**< The base hash engine. */
	struct hash_engine_openssl_state *state;	/**< Variable context for the hash engine. */
};


int hash_openssl_init (struct hash_engine_openssl *engine, struct hash_engine_openssl_state *state);
int hash_openssl_init_state (const struct hash_engine_openssl *engine);
void hash_openssl_release (const struct hash_engine_openssl *engine);


#endif /* HASH_OPENSSL_H_ */
