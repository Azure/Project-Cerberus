// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_OPENSSL_H_
#define AES_OPENSSL_H_

#include <openssl/evp.h>
#include "crypto/aes.h"


/**
 * An OpenSSL context for AES operations.
 */
struct aes_engine_openssl {
	struct aes_engine base;			/**< The base AES engine. */
	EVP_CIPHER_CTX *context;		/**< Context to use for AES operations. */
};


int aes_openssl_init (struct aes_engine_openssl *engine);
void aes_openssl_release (struct aes_engine_openssl *engine);


#endif /* AES_OPENSSL_H_ */
