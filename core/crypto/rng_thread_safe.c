// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rng_thread_safe.h"


static int rng_thread_safe_generate_random_buffer (struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	struct rng_engine_thread_safe *rng = (struct rng_engine_thread_safe*) engine;
	int status;

	if (rng == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rng->lock);
	status = rng->engine->generate_random_buffer (rng->engine, rand_len, buf);
	platform_mutex_unlock (&rng->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for an RNG engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int rng_thread_safe_init (struct rng_engine_thread_safe *engine, struct rng_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rng_engine_thread_safe));

	engine->base.generate_random_buffer = rng_thread_safe_generate_random_buffer;

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe RNG wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void rng_thread_safe_release (struct rng_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
