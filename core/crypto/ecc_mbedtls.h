// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_MBEDTLS_H_
#define ECC_MBEDTLS_H_

#include "ecc.h"
#include "rng.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


/**
 * Variable context for an mbedTLS ECC engine.
 */
struct ecc_engine_mbedtls_state {
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
};

/**
 * An mbedTLS context for ECC operations.
 */
struct ecc_engine_mbedtls {
	struct ecc_engine base;							/**< The base ECC engine. */
	struct ecc_engine_mbedtls_state *state;			/**< Variable context for the ECC engine. */
	void *rng;										/**< The source for random numbers. */
	int (*f_rng) (void*, unsigned char*, size_t);	/**< Callback function for retrieving random numbers. */
};


int ecc_mbedtls_init (struct ecc_engine_mbedtls *engine, struct ecc_engine_mbedtls_state *state);
int ecc_mbedtls_init_with_external_rng (struct ecc_engine_mbedtls *engine,
	const struct rng_engine *rng);
int ecc_mbedtls_init_state (const struct ecc_engine_mbedtls *engine);
void ecc_mbedtls_release (const struct ecc_engine_mbedtls *engine);


#endif	/* ECC_MBEDTLS_H_ */
