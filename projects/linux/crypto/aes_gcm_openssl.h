// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_GCM_OPENSSL_H_
#define AES_GCM_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes_gcm.h"


/**
 * Variable context for mbedTLS AES-GCM operations.
 */
struct aes_gcm_engine_openssl_state {
	EVP_CIPHER_CTX *context;	/**< Context to use for AES operations. */
};

/**
 * An OpenSSL context for AES-GCM operations.
 */
struct aes_gcm_engine_openssl {
	struct aes_gcm_engine base;					/**< The base AES engine. */
	struct aes_gcm_engine_openssl_state *state;	/**< Variable context for the AES engine. */
};


int aes_gcm_openssl_init (struct aes_gcm_engine_openssl *engine,
	struct aes_gcm_engine_openssl_state *state);
int aes_gcm_openssl_init_state (const struct aes_gcm_engine_openssl *engine);
void aes_gcm_openssl_release (const struct aes_gcm_engine_openssl *engine);


#endif	/* AES_GCM_OPENSSL_H_ */
