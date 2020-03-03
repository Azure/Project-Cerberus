// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "crypto/rng.h"
#include "rng_openssl.h"

static int rng_openssl_generate_random_buffer (struct rng_engine *engine, size_t rand_len,
	uint8_t *buf)
{
	struct rng_engine_openssl *openssl_engine = (struct rng_engine_openssl*) engine;

	if ((openssl_engine == NULL) || (buf == NULL)) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

    if (!RAND_bytes(buf, rand_len)) {
		return ERR_get_error ();
	}

	return 0;
}

/**
 * Initialize an OpenSSL engine for generating random numbers.
 *
 * @param engine The RNG engine to initialize.
 *
 * @return 0 if the RNG engine was initialized successfully or an error code.
 */
int rng_openssl_init (struct rng_engine_openssl *engine)
{
	if (engine == NULL) {
		return RNG_ENGINE_INVALID_ARGUMENT;
	}

	engine->base.generate_random_buffer = rng_openssl_generate_random_buffer;

	return 0;
}

/**
 * Release the resources used by an OpenSSL RNG engine.
 *
 * @param engine The RNG engine to release.
 */
void rng_openssl_release (struct rng_engine_openssl *engine)
{

}
