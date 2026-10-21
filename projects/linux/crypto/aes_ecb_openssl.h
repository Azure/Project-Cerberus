// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_ECB_OPENSSL_H_
#define AES_ECB_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes_ecb.h"


/**
 * Variable context for OpenSSL AES-ECB execution.
 */
struct aes_ecb_engine_openssl_state {
	EVP_CIPHER_CTX *encrypt;	/**< Context to use for encryption. */
	EVP_CIPHER_CTX *decrypt;	/**< Context to use for decryption. */
};

/**
 * An OpenSSL implementation for AES-ECB operations.
 */
struct aes_ecb_engine_openssl {
	struct aes_ecb_engine base;					/**< The base AES-ECB engine. */
	struct aes_ecb_engine_openssl_state *state;	/**< Variable context for the instance. */
};


int aes_ecb_openssl_init (struct aes_ecb_engine_openssl *engine,
	struct aes_ecb_engine_openssl_state *state);
int aes_ecb_openssl_init_state (const struct aes_ecb_engine_openssl *engine);
void aes_ecb_openssl_release (const struct aes_ecb_engine_openssl *engine);


#endif	/* AES_ECB_OPENSSL_H_ */
