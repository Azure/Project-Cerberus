// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_OPENSSL_H_
#define AES_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes.h"


/**
 * Variable context for mbedTLS AES-GCM operations.
 */
struct aes_engine_openssl_state {
	EVP_CIPHER_CTX *context;	/**< Context to use for AES operations. */
};

/**
 * An OpenSSL context for AES-GCM operations.
 */
struct aes_engine_openssl {
	struct aes_engine base;					/**< The base AES engine. */
	struct aes_engine_openssl_state *state;	/**< Variable context for the AES engine. */
};


int aes_openssl_init (struct aes_engine_openssl *engine, struct aes_engine_openssl_state *state);
int aes_openssl_init_state (const struct aes_engine_openssl *engine);
void aes_openssl_release (const struct aes_engine_openssl *engine);


#endif	/* AES_OPENSSL_H_ */
