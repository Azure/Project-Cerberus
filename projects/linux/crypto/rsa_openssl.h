// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_OPENSSL_H_
#define RSA_OPENSSL_H_

#include "crypto/rsa.h"


/**
 * An openssl context for RSA encryption.
 */
struct rsa_engine_openssl {
	struct rsa_engine base;		/**< The base RSA engine. */
};


int rsa_openssl_init (struct rsa_engine_openssl *engine);
void rsa_openssl_release (struct rsa_engine_openssl *engine);


#endif /* RSA_OPENSSL_H_ */
