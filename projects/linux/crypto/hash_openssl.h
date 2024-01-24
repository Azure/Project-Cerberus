// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_OPENSSL_H_
#define HASH_OPENSSL_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include "crypto/hash.h"


/**
 * An OpenSSL context for calculating hashes.
 */
struct hash_engine_openssl {
	struct hash_engine base;	/**< The base hash engine. */
	EVP_MD_CTX *sha;			/**< The context for calculating incremental hashes. */
	int active;					/**< The type of initialized context. */
};


int hash_openssl_init (struct hash_engine_openssl *engine);
void hash_openssl_release (struct hash_engine_openssl *engine);


#endif /* HASH_OPENSSL_H_ */
