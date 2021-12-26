// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_MBEDTLS_H_
#define HASH_MBEDTLS_H_

#include "hash.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"


/**
 * An mbedTLS context for calculating hashes.
 */
struct hash_engine_mbedtls {
	struct hash_engine base;			/**< The base hash engine. */
	union {
#ifdef HASH_ENABLE_SHA1
		mbedtls_sha1_context sha1;		/**< Context for SHA1 hashes. */
#endif
		mbedtls_sha256_context sha256;	/**< Context for SHA256 hashes. */
#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		mbedtls_sha512_context sha512;	/**< Context for SHA512 hashes. */
#endif
	} context;							/**< The hashing contexts. */
	uint8_t active;						/**< The active hash context. */
};


int hash_mbedtls_init (struct hash_engine_mbedtls *engine);
void hash_mbedtls_release (struct hash_engine_mbedtls *engine);


#endif /* HASH_MBEDTLS_H_ */
