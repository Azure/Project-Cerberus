// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_THREAD_SAFE_STATIC_H_
#define RNG_THREAD_SAFE_STATIC_H_

#include "rng_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int rng_thread_safe_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf);


/**
 * Constant initializer for the RNG API.
 */
#define	RNG_THREAD_SAFE_API_INIT { \
		.generate_random_buffer = rng_thread_safe_generate_random_buffer, \
	}


/**
 * Initialize a static thread-safe wrapper for an RNG engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state Variable context for the thread-safe wrapper.
 * @param target The target engine that will be used to execute operations.
 */
#define	rng_thread_safe_static_init(state_ptr, target_ptr) { \
		.base = RNG_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* RNG_THREAD_SAFE_STATIC_H_ */
