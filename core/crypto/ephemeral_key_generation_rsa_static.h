// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EPHEMERAL_KEY_GENERATION_RSA_STATIC_H_
#define EPHEMERAL_KEY_GENERATION_RSA_STATIC_H_

#include <stdint.h>
#include <string.h>
#include "crypto/ephemeral_key_generation_rsa.h"
#include "crypto/rsa.h"


/* Internal functions declared to allow for static initialization. */
int ephemeral_key_gen_rsa_generate_key (const struct ephemeral_key_generation *ephemeral_key_gen,
	int bits, uint8_t **key, size_t *key_length);


/**
 * Constant initializer for the Ephemeral Key generation RSA API.
 */
#define	EPHEMERAL_KEY_GENERATION_RSA_API_STATIC_INIT { \
		.generate_key = ephemeral_key_gen_rsa_generate_key, \
	}

/**
 * Static initialization of ephemeral key generation RSA.
 * There is no validation done on the arguments.
 *
 * @param[in]	engine_ptr	A pointer to an implementation of RSA engine object
 */
#define	ephemeral_key_generation_rsa_static_init(engine_ptr) { \
		.base = EPHEMERAL_KEY_GENERATION_RSA_API_STATIC_INIT, \
		.engine = engine_ptr, \
	}


#endif	/* EPHEMERAL_KEY_GENERATION_RSA_STATIC_H_ */
