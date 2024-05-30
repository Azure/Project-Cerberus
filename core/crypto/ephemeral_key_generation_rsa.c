// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "platform_io.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "crypto/ephemeral_key_generation_rsa.h"


int ephemeral_key_gen_rsa_generate_key (const struct ephemeral_key_generation *ephemeral_key_gen,
	int key_size, uint8_t **key, size_t *key_length)
{
	int status = 0;

	if ((ephemeral_key_gen == NULL) || (key == NULL) || (key_length == NULL)) {
		return EPHEMERAL_KEY_GEN_INVALID_ARGUMENT;
	}

#if (defined RSA_ENABLE_PRIVATE_KEY)
	struct rsa_private_key rsa_key;
	const struct ephemeral_key_generation_rsa *key_gen_rsa =
		TO_DERIVED_TYPE (ephemeral_key_gen, const struct ephemeral_key_generation_rsa, base);

	status = key_gen_rsa->engine->generate_key (key_gen_rsa->engine, &rsa_key, key_size);
	if (status != 0) {
		return status;
	}

	/* Get Private key DER data */
	status = key_gen_rsa->engine->get_private_key_der (key_gen_rsa->engine,	&rsa_key, key,
		key_length);

	key_gen_rsa->engine->release_key (key_gen_rsa->engine, &rsa_key);

#else
	UNUSED (ephemeral_key_gen);
	UNUSED (key_size);
	status = EPHEMERAL_KEY_GEN_PRIVATE_KEY_GEN_UNSUPPORTED;
#endif

	return status;
}

/**
 * Initialize an ephemeral key generation RSA engine.
 *
 * @param key_gen_rsa - A pointer to ephemeral key generation RSA object.
 * @param engine  - The RSA engine to initialize.
 *
 * @return 0 if the RSA engine was successfully initialized or an error code.
 */
int ephemeral_key_generation_rsa_init (struct ephemeral_key_generation_rsa *key_gen_rsa,
	struct rsa_engine *engine)
{
	if ((key_gen_rsa == NULL) || (engine == NULL)) {
		return EPHEMERAL_KEY_GEN_INVALID_ARGUMENT;
	}

	memset (key_gen_rsa, 0, sizeof (struct ephemeral_key_generation_rsa));

	key_gen_rsa->engine = engine;

	/* Assign API to generate RSA Key using mbedTLS API */
	key_gen_rsa->base.generate_key = ephemeral_key_gen_rsa_generate_key;

	return 0;
}

/**
 * Release the resources used by an ephemeral key generation RSA.
 *
 * @param engine The RSA engine to release.
 */
void ephemeral_key_generation_rsa_release (
	struct ephemeral_key_generation_rsa *key_gen_rsa)
{
	UNUSED (key_gen_rsa);
}
