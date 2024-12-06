// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_io.h"
#include "rng_dummy.h"
#include "common/unused.h"


/* Parameters used to generate "random" numbers. */
#define	RNG_DUMMY_MULT		15
#define	RNG_DUMMY_XOR		0x78879EBC


int rng_dummy_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	const struct rng_engine_dummy *dummy = (const struct rng_engine_dummy*) engine;
	size_t copy_len;

	if ((dummy == NULL) || (buf == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	while (rand_len > 0) {
		copy_len = (rand_len >= sizeof (uint32_t)) ? sizeof (uint32_t) : rand_len;
		memcpy (buf, &dummy->state->random, copy_len);

		buf += copy_len;
		rand_len -= copy_len;

		dummy->state->random = (dummy->state->random * RNG_DUMMY_MULT) ^ RNG_DUMMY_XOR;
	}

	return 0;
}

/**
 * Initialize a dummy RNG for testing or development environments without a real random number
 * generator.
 *
 * @param rng The dummy RNG to initialize.
 * @param state Variable context for the RNG engine.  This must be uninitialized.
 * @param seed A seed to use for generating the random numbers.
 *
 * @return 0 if the RNG was successfully initialized or an error code.
 */
int rng_dummy_init (struct rng_engine_dummy *rng, struct rng_engine_dummy_state *state,
	uint32_t seed)
{
	if (rng == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (rng, 0, sizeof (struct rng_engine_dummy));

	rng->base.generate_random_buffer = rng_dummy_generate_random_buffer;

	rng->state = state;

	return rng_dummy_init_state (rng, seed);
}

/**
 * Initialize only the variable state of a dummy RNG for testing or development environments.  The
 * rest of the instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The RNG engine that contains the state to initialize.
 * @param seed A seed to use for generating the random numbers.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int rng_dummy_init_state (const struct rng_engine_dummy *rng, uint32_t seed)
{
	if ((rng == NULL) || (rng->state == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (rng->state, 0, sizeof (*rng->state));

	rng->state->random = (seed * RNG_DUMMY_MULT) ^ RNG_DUMMY_XOR;

	return 0;
}

/**
 * Release the resources used by a dummy RNG.
 *
 * @param rng The dummy RNG to release.
 *
 */
void rng_dummy_release (const struct rng_engine_dummy *rng)
{
	UNUSED (rng);
}
