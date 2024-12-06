// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_MBEDTLS_STATIC_H_
#define RNG_MBEDTLS_STATIC_H_

#include "rng_mbedtls.h"


/* Internal functions declared to allow for static initialization. */
int rng_mbedtls_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf);


/**
 * Constant initializer for the RNG API.
 */
#define	RNG_MBEDTLS_API_INIT { \
		.generate_random_buffer = rng_mbedtls_generate_random_buffer, \
	}


/**
 * Initialize a static mbedTLS engine for generating random numbers using a software DRBG.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for RNG operations.
 */
#define	rng_mbedtls_static_init(state_ptr) { \
		.base = RNG_MBEDTLS_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* RNG_MBEDTLS_STATIC_H_ */
