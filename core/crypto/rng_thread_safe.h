// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_THREAD_SAFE_H_
#define RNG_THREAD_SAFE_H_

#include "platform_api.h"
#include "crypto/rng.h"


/**
 * Variable context for a thread-safe RNG wrapper.
 */
struct rng_engine_thread_safe_state {
	platform_mutex lock;	/**< Synchronization lock. */
};

/**
 * Thread-safe wrapper for an RNG instance.
 */
struct rng_engine_thread_safe {
	struct rng_engine base;						/**< Base API implementation. */
	struct rng_engine_thread_safe_state *state;	/**< Variable context for the RNG wrapper. */
	const struct rng_engine *engine;			/**< RNG instance to use for execution. */
};


int rng_thread_safe_init (struct rng_engine_thread_safe *engine,
	struct rng_engine_thread_safe_state *state, const struct rng_engine *target);
int rng_thread_safe_init_state (const struct rng_engine_thread_safe *engine);
void rng_thread_safe_release (const struct rng_engine_thread_safe *engine);


#endif	/* RNG_THREAD_SAFE_H_ */
