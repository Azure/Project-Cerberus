// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "platform_io.h"
#include "common/unused.h"
#include "crypto/ephemeral_key_generation_rsa.h"


int ephemeral_key_generation_rsa_generate_key (const struct ephemeral_key_generation *key_gen,
	size_t key_size, uint8_t **key, size_t *key_length)
{
	struct rsa_private_key rsa_key;
	const struct ephemeral_key_generation_rsa *key_gen_rsa =
		(const struct ephemeral_key_generation_rsa*) key_gen;
	int status = 0;

	if (key == NULL) {
		return EPHEMERAL_KEY_GEN_INVALID_ARGUMENT;
	}

	*key = NULL;

	if ((key_gen == NULL) || (key_length == NULL)) {
		return EPHEMERAL_KEY_GEN_INVALID_ARGUMENT;
	}

	status = key_gen_rsa->engine->generate_key (key_gen_rsa->engine, &rsa_key, key_size);
	if (status != 0) {
		return status;
	}

	/* TODO:  Needs pairwise consistency test. */

	/* Get Private key DER data */
	status = key_gen_rsa->engine->get_private_key_der (key_gen_rsa->engine,	&rsa_key, key,
		key_length);

	key_gen_rsa->engine->release_key (key_gen_rsa->engine, &rsa_key);

	return status;
}

/**
 * Initialize an RSA ephemeral key generator.
 *
 * @param key_gen_rsa The RSA key generator to initialize.
 * @param engine The RSA engine to use for key generation.
 *
 * @return 0 if the key generator was successfully initialized or an error code.
 */
int ephemeral_key_generation_rsa_init (struct ephemeral_key_generation_rsa *key_gen_rsa,
	struct rsa_engine *engine)
{
	if ((key_gen_rsa == NULL) || (engine == NULL)) {
		return EPHEMERAL_KEY_GEN_INVALID_ARGUMENT;
	}

	memset (key_gen_rsa, 0, sizeof (struct ephemeral_key_generation_rsa));

	key_gen_rsa->engine = engine;

	key_gen_rsa->base.generate_key = ephemeral_key_generation_rsa_generate_key;

	return 0;
}

/**
 * Release the resources used by an RSA ephemeral key generator.
 *
 * @param engine The key generator to release.
 */
void ephemeral_key_generation_rsa_release (struct ephemeral_key_generation_rsa *key_gen_rsa)
{
	UNUSED (key_gen_rsa);
}
