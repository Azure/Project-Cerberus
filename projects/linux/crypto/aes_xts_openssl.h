// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_XTS_OPENSSL_H_
#define AES_XTS_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes_xts.h"


/**
 * Variable context for OpenSSL AES-XTS execution.
 */
struct aes_xts_engine_openssl_state {
	EVP_CIPHER_CTX *encrypt;	/**< Context to use for encryption. */
	EVP_CIPHER_CTX *decrypt;	/**< Context to use for decryption. */
};

/**
 * An OpenSSL implementation for AES-XTS operations.
 */
struct aes_xts_engine_openssl {
	struct aes_xts_engine base;					/**< The base AES-XTS engine. */
	struct aes_xts_engine_openssl_state *state;	/**< Variable context for the instance. */
};


int aes_xts_openssl_init (struct aes_xts_engine_openssl *engine,
	struct aes_xts_engine_openssl_state *state);
int aes_xts_openssl_init_state (const struct aes_xts_engine_openssl *engine);
void aes_xts_openssl_release (const struct aes_xts_engine_openssl *engine);


#endif	/* AES_XTS_OPENSSL_H_ */
