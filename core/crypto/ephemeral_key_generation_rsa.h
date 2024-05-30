// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EPHEMERAL_KEY_GENERATION_RSA_H_
#define EPHEMERAL_KEY_GENERATION_RSA_H_

#include <stdint.h>
#include <string.h>
#include "crypto/ephemeral_key_generation.h"
#include "crypto/rsa.h"


/**
 * Ephemeral key generation implementation for RSA private key generation.
 */
struct ephemeral_key_generation_rsa {
	struct ephemeral_key_generation base;	/**< Ephemeral key generation object */
	struct rsa_engine *engine;				/**< The base RSA engine. */
};


int ephemeral_key_generation_rsa_init (struct ephemeral_key_generation_rsa *key_gen_rsa,
	struct rsa_engine *engine);
void ephemeral_key_generation_rsa_release (
	struct ephemeral_key_generation_rsa *key_gen_rsa);


#endif	/* EPHEMERAL_KEY_GENERATION_RSA_H_ */
