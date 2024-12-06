// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "rng_mbedtls.h"


int rng_mbedtls_generate_random_buffer (const struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	const struct rng_engine_mbedtls *mbedtls = (const struct rng_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (buf == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	return mbedtls_ctr_drbg_random (&mbedtls->state->ctr_drbg, buf, rand_len);
}

/**
 * Initialize an mbedTLS engine for generating random numbers using a software DRBG.
 *
 * @param engine The mbedTLS RNG engine to initialize.
 * @param state Variable context for the RNG engine.  This must be uninitialized.
 *
 * @return 0 if the RNG engine was initialized successfully or an error code.
 */
int rng_mbedtls_init (struct rng_engine_mbedtls *engine, struct rng_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (*engine));

	engine->base.generate_random_buffer = rng_mbedtls_generate_random_buffer;

	engine->state = state;

	return rng_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS DRBG.  The rest of the instance is assumed to
 * already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The RNG engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int rng_mbedtls_init_state (const struct rng_engine_mbedtls *engine)
{
	int status;

	if ((engine == NULL) || (engine->state == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_ctr_drbg_init (&engine->state->ctr_drbg);
	mbedtls_entropy_init (&engine->state->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->state->ctr_drbg, mbedtls_entropy_func,
		&engine->state->entropy, NULL, 0);
	if (status != 0) {
		rng_mbedtls_release (engine);

		return status;
	}

	return 0;
}

/**
 * Release the resources used by an mbedTLS RNG engine.
 *
 * @param engine The mbedTLS RNG engine to release.
 */
void rng_mbedtls_release (const struct rng_engine_mbedtls *engine)
{
	if (engine != NULL) {
		mbedtls_ctr_drbg_free (&engine->state->ctr_drbg);
		mbedtls_entropy_free (&engine->state->entropy);
	}
}
