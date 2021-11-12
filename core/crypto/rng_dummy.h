// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_DUMMY_H_
#define RNG_DUMMY_H_

#include "crypto/rng.h"


/**
 * A RNG engine that returns "random" numbers from a seed using a very simple, deterministc method.
 * It is not cryptographically sound and must not be used in any production code.  It is mainly
 * useful in scenarios where any other RNG is not possible, which could be in test or development
 * environments.
 */
struct rng_engine_dummy {
	struct rng_engine base;			/**< Base RNG instance. */
	uint32_t random;				/**< The next random value. */
};


int rng_dummy_init (struct rng_engine_dummy *rng, uint32_t seed);
void rng_dummy_release (struct rng_engine_dummy *rng);


#endif /* RNG_DUMMY_H_ */
