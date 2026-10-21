// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef AES_CBC_OPENSSL_20COPY_H_
#define AES_CBC_OPENSSL_20COPY_H_
// Licensed under the MIT license.

#ifndef AES_CBC_OPENSSL_H_
#define AES_CBC_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes_cbc.h"


/**
 * Variable context for OpenSSL AES-CBC execution.
 */
struct aes_cbc_engine_openssl_state {
	EVP_CIPHER_CTX *encrypt;	/**< Context to use for encryption. */
	EVP_CIPHER_CTX *decrypt;	/**< Context to use for decryption. */
};

/**
 * An OpenSSL implementation for AES-CBC operations.
 */
struct aes_cbc_engine_openssl {
	struct aes_cbc_engine base;					/**< The base AES-CBC engine. */
	struct aes_cbc_engine_openssl_state *state;	/**< Variable context for the instance. */
};


int aes_cbc_openssl_init (struct aes_cbc_engine_openssl *engine,
	struct aes_cbc_engine_openssl_state *state);
int aes_cbc_openssl_init_state (const struct aes_cbc_engine_openssl *engine);
void aes_cbc_openssl_release (const struct aes_cbc_engine_openssl *engine);


#endif	/* AES_CBC_OPENSSL_H_ */


#endif	/* AES_CBC_OPENSSL_20COPY_H_ */
