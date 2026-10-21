// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_MBEDTLS_H_
#define RSA_MBEDTLS_H_

#include "rng.h"
#include "rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/**
 * Variable context for mbedTLS RSA operations.
 */
struct rsa_engine_mbedtls_state {
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
};

/**
 * An mbedTLS context for RSA encryption.
 */
struct rsa_engine_mbedtls {
	struct rsa_engine base;							/**< The base RSA engine. */
	struct rsa_engine_mbedtls_state *state;			/**< Variable context for the RSA engine. */
	void *rng;										/**< The source for random numbers. */
	int (*f_rng) (void*, unsigned char*, size_t);	/**< Callback function for retrieving random numbers. */
};


int rsa_mbedtls_init (struct rsa_engine_mbedtls *engine, struct rsa_engine_mbedtls_state *state);
int rsa_mbedtls_init_with_external_rng (struct rsa_engine_mbedtls *engine,
	const struct rng_engine *rng);
int rsa_mbedtls_init_state (const struct rsa_engine_mbedtls *engine);
void rsa_mbedtls_release (const struct rsa_engine_mbedtls *engine);


#endif	/* RSA_MBEDTLS_H_ */
