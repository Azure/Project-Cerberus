// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_RIOT_H_
#define ECC_RIOT_H_

#include "crypto/ecc.h"
#include "crypto/rng.h"


/**
 * A riot context for ECC operations.
 * 
 * NOTE: The following crypto engine API routines are not implemented and the corresponding
 * function pointers are set to NULL: init_public_key, generate_key_pair,
 * get_shared_secret_max_length, and compute_shared_secret.
 */
struct ecc_engine_riot {
	struct ecc_engine base;				/**< The base ECC engine. */
	struct rng_engine *rng;				/**< A random number generator for the ECC engine. */
};


int ecc_riot_init (struct ecc_engine_riot *engine, struct rng_engine *rng);
void ecc_riot_release (struct ecc_engine_riot *engine);


#endif /* ECC_RIOT_H_ */
