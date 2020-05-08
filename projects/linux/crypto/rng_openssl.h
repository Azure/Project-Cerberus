// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_OPENSSL_H_
#define RNG_OPENSSL_H_

#include <stdint.h>
#include "crypto/rng.h"


/**
 * An openssl context for RNG operations.
 */
struct rng_engine_openssl {
	struct rng_engine base;		/**< The base RNG engine. */
};

int rng_openssl_init (struct rng_engine_openssl *engine);
void rng_openssl_release (struct rng_engine_openssl *engine);


#endif // RNG_OPENSSL_H_