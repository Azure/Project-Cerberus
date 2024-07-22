// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_MBEDTLS_H_
#define AES_MBEDTLS_H_

#include "aes.h"
#include "mbedtls/gcm.h"


/**
 * State information for a mbedTLS AES engine.
 */
struct aes_engine_mbedtls_state {
	mbedtls_gcm_context context;	/**< The mbedTLS GCM context. */
};

/**
 * An mbedTLS context for AES operations.
 */
struct aes_engine_mbedtls {
	struct aes_engine base;					/**< The base AES engine. */
	struct aes_engine_mbedtls_state *state;	/**< The state information for the engine. */
};


int aes_mbedtls_init (struct aes_engine_mbedtls *engine, struct aes_engine_mbedtls_state *state);
int aes_mbedtls_init_state (const struct aes_engine_mbedtls *engine);
void aes_mbedtls_release (const struct aes_engine_mbedtls *engine);


#endif	/* AES_MBEDTLS_H_ */
