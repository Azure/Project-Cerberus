// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_MBEDTLS_H_
#define RNG_MBEDTLS_H_

#include "crypto/rng.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/**
 * Variable context for the mbedTLS DRBG.
 */
struct rng_engine_mbedtls_state {
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
};

/**
 * An mbedTLS context for RNG operations, using a software DRBG.
 */
struct rng_engine_mbedtls {
	struct rng_engine base;					/**< The base RNG engine. */
	struct rng_engine_mbedtls_state *state;	/**< Variable context for the RNG engine. */
};


int rng_mbedtls_init (struct rng_engine_mbedtls *engine, struct rng_engine_mbedtls_state *state);
int rng_mbedtls_init_state (const struct rng_engine_mbedtls *engine);
void rng_mbedtls_release (const struct rng_engine_mbedtls *engine);


#endif	// RNG_MBEDTLS_H_
