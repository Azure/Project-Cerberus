// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_OPENSSL_H_
#define HASH_OPENSSL_H_

#include <openssl/sha.h>
#include "crypto/hash.h"


/**
 * An OpenSSL context for calculating hashes.
 */
struct hash_engine_openssl {
	struct hash_engine base;	/**< The base hash engine. */
#ifdef HASH_ENABLE_SHA1
	SHA_CTX	sha1;				/**< The context for calculating SHA1 incremental hashes. */
#endif
	SHA256_CTX sha256;			/**< The context for calculating SHA256 incremental hashes. */
#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
	SHA512_CTX sha512;			/**< The context for calculating SHA384/SHA512 incremental hashes. */
#endif
	int active;					/**< The type of initialized context. */
};


int hash_openssl_init (struct hash_engine_openssl *engine);
void hash_openssl_release (struct hash_engine_openssl *engine);


#endif /* HASH_OPENSSL_H_ */
