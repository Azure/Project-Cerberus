// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rng_thread_safe.h"


int rng_thread_safe_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	const struct rng_engine_thread_safe *rng = (const struct rng_engine_thread_safe*) engine;
	int status;

	if (rng == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rng->state->lock);
	status = rng->engine->generate_random_buffer (rng->engine, rand_len, buf);
	platform_mutex_unlock (&rng->state->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for an RNG engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param state Variable context for the thread-safe wrapper. This must be uninitialized.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int rng_thread_safe_init (struct rng_engine_thread_safe *engine,
	struct rng_engine_thread_safe_state *state, const struct rng_engine *target)
{
	if (engine == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rng_engine_thread_safe));

	engine->base.generate_random_buffer = rng_thread_safe_generate_random_buffer;

	engine->state = state;
	engine->engine = target;

	return rng_thread_safe_init_state (engine);
}

/**
 * Initialize only the variable state of a thread-safe wrapper for an RNG engine.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The RNG engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int rng_thread_safe_init_state (const struct rng_engine_thread_safe *engine)
{
	if ((engine == NULL) || (engine->state == NULL) || (engine->engine == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	return platform_mutex_init (&engine->state->lock);
}

/**
 * Release the resources used for a thread-safe RNG wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void rng_thread_safe_release (const struct rng_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->state->lock);
	}
}
