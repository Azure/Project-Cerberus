// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rng_dummy.h"
#include "common/unused.h"
#include "platform_io.h"


/* Parameters used to generate "random" numbers. */
#define	RNG_DUMMY_MULT		15
#define	RNG_DUMMY_XOR		0x78879EBC


static int rng_dummy_generate_random_buffer (struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	struct rng_engine_dummy *dummy = (struct rng_engine_dummy*) engine;
	size_t copy_len;

	if ((dummy == NULL) || (buf == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	while (rand_len > 0) {
		copy_len = (rand_len >= sizeof (uint32_t)) ? sizeof (uint32_t) : rand_len;
		memcpy (buf, &dummy->random, copy_len);

		buf += copy_len;
		rand_len -= copy_len;

		dummy->random = (dummy->random * RNG_DUMMY_MULT) ^ RNG_DUMMY_XOR;
	}

	return 0;
}

/**
 * Initialize a dummy RNG for testing or development environments without a real random number
 * generator.
 *
 * @param rng The dummy RNG to initialize.
 * @param seed A seed to use for generating the random numbers.
 *
 * @return 0 if the RNG was successfully initialized or an error code.
 */
int rng_dummy_init (struct rng_engine_dummy *rng, uint32_t seed)
{
	if (rng == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (rng, 0, sizeof (struct rng_engine_dummy));

	rng->base.generate_random_buffer = rng_dummy_generate_random_buffer;

	rng->random = (seed * RNG_DUMMY_MULT) ^ RNG_DUMMY_XOR;

	return 0;
}

/**
 * Release the resources used by a dummy RNG.
 *
 * @param rng The dummy RNG to release.
 *
 */
void rng_dummy_release (struct rng_engine_dummy *rng)
{
	UNUSED (rng);
}
