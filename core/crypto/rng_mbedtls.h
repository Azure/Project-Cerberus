// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_MBEDTLS_H_
#define RNG_MBEDTLS_H_

#include "crypto/rng.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/**
 * An mbedTLS context for RNG operations.
 */
struct rng_engine_mbedtls {
	struct rng_engine base;				/**< The base RNG engine. */
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
};


int rng_mbedtls_init (struct rng_engine_mbedtls *engine);
void rng_mbedtls_release (struct rng_engine_mbedtls *engine);


#endif // RNG_MBEDTLS_H_
