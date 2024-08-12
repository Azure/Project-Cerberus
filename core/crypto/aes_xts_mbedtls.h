// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_XTS_MBEDTLS_H_
#define AES_XTS_MBEDTLS_H_

#include <stdbool.h>
#include "aes_xts.h"
#include "mbedtls/aes.h"


/**
 * Variable context for mbedTLS AES-XTS execution.
 */
struct aes_xts_engine_mbedtls_state {
	mbedtls_aes_xts_context encrypt;	/**< XTS encryption context. */
	mbedtls_aes_xts_context decrypt;	/**< XTS decryption context. */
	bool has_key;						/**< Flag indicating if the encryption key has been set. */
};

/**
 * An mbedTLS implementation for AES-XTS operations.
 */
struct aes_xts_engine_mbedtls {
	struct aes_xts_engine base;					/**< The base AES-XTS engine. */
	struct aes_xts_engine_mbedtls_state *state;	/**< Variable context for the instance. */
};


int aes_xts_mbedtls_init (struct aes_xts_engine_mbedtls *engine,
	struct aes_xts_engine_mbedtls_state *state);
int aes_xts_mbedtls_init_state (const struct aes_xts_engine_mbedtls *engine);
void aes_xts_mbedtls_release (const struct aes_xts_engine_mbedtls *engine);


#endif	/* AES_XTS_MBEDTLS_H_ */
