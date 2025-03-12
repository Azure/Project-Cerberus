// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_ECB_MBEDTLS_STATIC_H_
#define AES_ECB_MBEDTLS_STATIC_H_

#include "crypto/aes_ecb_mbedtls.h"


/* Internal functions declared to allow for static initialization. */
int aes_ecb_mbedtls_set_key (const struct aes_ecb_engine *engine, const uint8_t *key,
	size_t length);
int aes_ecb_mbedtls_clear_key (const struct aes_ecb_engine *engine);
int aes_ecb_mbedtls_encrypt_data (const struct aes_ecb_engine *engine, const uint8_t *plaintext,
	size_t length, uint8_t *ciphertext, size_t out_length);
int aes_ecb_mbedtls_decrypt_data (const struct aes_ecb_engine *engine, const uint8_t *ciphertext,
	size_t length, uint8_t *plaintext, size_t out_length);


/**
 * Constant initializer for the AES-ECB API.
 */
#define	AES_ECB_MBEDTLS_API_INIT { \
		.set_key = aes_ecb_mbedtls_set_key, \
		.clear_key = aes_ecb_mbedtls_clear_key, \
		.encrypt_data = aes_ecb_mbedtls_encrypt_data, \
		.decrypt_data = aes_ecb_mbedtls_decrypt_data, \
	}


/**
 * Initialize a static instance for running AES-ECB operations using mbedTLS.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for AES operations.
 */
#define	aes_ecb_mbedtls_static_init(state_ptr) { \
		.base = AES_ECB_MBEDTLS_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_ECB_MBEDTLS_STATIC_H_ */
