// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_DUMMY_STATIC_H_
#define RNG_DUMMY_STATIC_H_

#include "rng_dummy.h"


/* Internal functions declared to allow for static initialization. */
int rng_dummy_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf);


/**
 * Constant initializer for the RNG API.
 */
#define	RNG_DUMMY_API_INIT { \
		.generate_random_buffer = rng_dummy_generate_random_buffer, \
	}


/**
 * Initialize a static dummy RNG for testing or development environments without a real random
 * number generator.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for RNG operations.
 */
#define	rng_dummy_static_init(state_ptr) { \
		.base = RNG_DUMMY_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* RNG_DUMMY_STATIC_H_ */
