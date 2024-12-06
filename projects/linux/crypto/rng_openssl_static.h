// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_OPENSSL_STATIC_H_
#define RNG_OPENSSL_STATIC_H_

#include "rng_openssl.h"


/* Internal functions declared to allow for static initialization. */
int rng_openssl_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf);


/**
 * Constant initializer for the RNG API.
 */
#define	RNG_OPENSSL_API_INIT { \
		.generate_random_buffer = rng_openssl_generate_random_buffer, \
	}


/**
 * Initialize a static OpenSSL engine for generating random numbers.
 */
#define	rng_openssl_static_init { \
		.base = RNG_OPENSSL_API_INIT, \
	}


#endif /* RNG_OPENSSL_STATIC_H_ */
