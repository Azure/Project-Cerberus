// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RNG_THREAD_SAFE_H_
#define RNG_THREAD_SAFE_H_

#include "platform.h"
#include "crypto/rng.h"


/**
 * Thread-safe wrapper for an RNG instance.
 */
struct rng_engine_thread_safe {
	struct rng_engine base;				/**< Base API implementation. */
	struct rng_engine *engine;			/**< RNG instance to use for execution. */
	platform_mutex lock;				/**< Synchronization lock. */
};


int rng_thread_safe_init (struct rng_engine_thread_safe *engine, struct rng_engine *target);
void rng_thread_safe_release (struct rng_engine_thread_safe *engine);


#endif /* RNG_THREAD_SAFE_H_ */
