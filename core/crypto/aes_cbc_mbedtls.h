// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_CBC_MBEDTLS_H_
#define AES_CBC_MBEDTLS_H_

#include <stdbool.h>
#include "aes_cbc.h"
#include "mbedtls/aes.h"


/**
 * Variable context for mbedTLS AES-CBC execution.
 */
struct aes_cbc_engine_mbedtls_state {
	mbedtls_aes_context encrypt;	/**< AES encryption context. */
	mbedtls_aes_context decrypt;	/**< AES decryption context. */
	bool has_key;					/**< Flag indicating if the encryption key has been set. */
};

/**
 * An mbedTLS implementation for AES-CBC operations.
 */
struct aes_cbc_engine_mbedtls {
	struct aes_cbc_engine base;					/**< The base AES-CBC engine. */
	struct aes_cbc_engine_mbedtls_state *state;	/**< Variable context for the instance. */
};


int aes_cbc_mbedtls_init (struct aes_cbc_engine_mbedtls *engine,
	struct aes_cbc_engine_mbedtls_state *state);
int aes_cbc_mbedtls_init_state (const struct aes_cbc_engine_mbedtls *engine);
void aes_cbc_mbedtls_release (const struct aes_cbc_engine_mbedtls *engine);


#endif	/* AES_CBC_MBEDTLS_H_ */
