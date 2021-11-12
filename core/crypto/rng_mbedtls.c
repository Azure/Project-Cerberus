// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include "rng_mbedtls.h"


static int rng_mbedtls_generate_random_buffer (struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	struct rng_engine_mbedtls *mbedtls_engine = (struct rng_engine_mbedtls*) engine;

	if ((mbedtls_engine == NULL) || (buf == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	return mbedtls_ctr_drbg_random (&mbedtls_engine->ctr_drbg, buf, rand_len);
}

/**
 * Initialize an mbedTLS engine for generating random numbers.
 *
 * @param engine The mbedTLS RNG engine to initialize.
 *
 * @return 0 if the RNG engine was initialized successfully or an error code.
 */
int rng_mbedtls_init (struct rng_engine_mbedtls *engine)
{
	int status;

	if (engine == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	mbedtls_ctr_drbg_init (&engine->ctr_drbg);
	mbedtls_entropy_init (&engine->entropy);

    status = mbedtls_ctr_drbg_seed (&engine->ctr_drbg, mbedtls_entropy_func, &engine->entropy, NULL,
		0);
	if (status != 0) {
		rng_mbedtls_release (engine);
		return status;
    }

	engine->base.generate_random_buffer = rng_mbedtls_generate_random_buffer;

	return 0;
}

/**
 * Release the resources used by an mbedTLS RNG engine.
 *
 * @param engine The mbedTLS RNG engine to release.
 */
void rng_mbedtls_release (struct rng_engine_mbedtls *engine)
{
	if (engine != NULL) {
		mbedtls_ctr_drbg_free (&engine->ctr_drbg);
		mbedtls_entropy_free (&engine->entropy);
	}
}
