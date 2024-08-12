// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_MBEDTLS_STATIC_H_
#define AES_MBEDTLS_STATIC_H_

#include "crypto/aes_mbedtls.h"


/* Internal functions declared to allow for static initialization. */
int aes_mbedtls_set_key (struct aes_engine *engine, const uint8_t *key, size_t length);
int aes_mbedtls_encrypt_data (struct aes_engine *engine, const uint8_t *plaintext, size_t length,
	const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
	size_t tag_length);
int aes_mbedtls_encrypt_with_add_data (struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, const uint8_t *additional_data,
	size_t additional_data_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
	size_t tag_length);
int aes_mbedtls_decrypt_data (struct aes_engine *engine, const uint8_t *ciphertext,	size_t length,
	const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext, size_t out_length);
int aes_mbedtls_decrypt_with_add_data (struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length,
	const uint8_t *additional_data, size_t additional_data_length, uint8_t *plaintext,
	size_t out_length);

/**
 * Constant initializer for the AES-GCM API.
 */
#define	AES_MBEDTLS_API_STATIC_INIT { \
		.set_key = aes_mbedtls_set_key, \
		.encrypt_data = aes_mbedtls_encrypt_data, \
		.encrypt_with_add_data = aes_mbedtls_encrypt_with_add_data, \
		.decrypt_data = aes_mbedtls_decrypt_data, \
		.decrypt_with_add_data = aes_mbedtls_decrypt_with_add_data, \
	}

/**
 * Static initialization of AES Mbedtls engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Pointer to the state information for the engine.
 */
#define	aes_mbedtls_static_init(state_ptr) { \
		.base = AES_MBEDTLS_API_STATIC_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_MBEDTLS_STATIC_H_ */
