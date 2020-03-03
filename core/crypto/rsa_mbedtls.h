// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_MBEDTLS_H_
#define RSA_MBEDTLS_H_

#include "rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/**
 * An mbedTLS context for RSA encryption.
 */
struct rsa_engine_mbedtls {
	struct rsa_engine base;				/**< The base RSA engine. */
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
};


int rsa_mbedtls_init (struct rsa_engine_mbedtls *engine);
void rsa_mbedtls_release (struct rsa_engine_mbedtls *engine);


#endif /* RSA_MBEDTLS_H_ */
