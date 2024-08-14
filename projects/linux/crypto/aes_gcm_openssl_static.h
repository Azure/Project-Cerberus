// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_GCM_OPENSSL_STATIC_H_
#define AES_GCM_OPENSSL_STATIC_H_

#include "aes_xts_openssl.h"


/* Internal functions declared to allow for static initialization. */
int aes_gcm_openssl_set_key (const struct aes_gcm_engine *engine, const uint8_t *key,
	size_t length);
int aes_gcm_openssl_encrypt_data (const struct aes_gcm_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length);
int aes_gcm_openssl_encrypt_with_add_data (const struct aes_gcm_engine *engine,
	const uint8_t *plaintext, size_t length, const uint8_t *iv, size_t iv_length,
	const uint8_t *additional_data,	size_t additional_data_length, uint8_t *ciphertext,
	size_t out_length, uint8_t *tag, size_t tag_length);
int aes_gcm_openssl_decrypt_data (const struct aes_gcm_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length);
int aes_gcm_openssl_decrypt_with_add_data (const struct aes_gcm_engine *engine,
	const uint8_t *ciphertext, size_t length, const uint8_t *tag, const uint8_t *iv,
	size_t iv_length, const uint8_t *additional_data, size_t additional_data_length,
	uint8_t *plaintext,	size_t out_length);


/**
 * Constant initializer for the AES-GCM API.
 */
#define	AES_GCM_OPENSSL_API_INIT	{ \
		.set_key = aes_gcm_openssl_set_key, \
		.encrypt_data = aes_gcm_openssl_encrypt_data, \
		.encrypt_with_add_data = aes_gcm_openssl_encrypt_with_add_data, \
		.decrypt_data = aes_gcm_openssl_decrypt_data, \
		.decrypt_with_add_data = aes_gcm_openssl_decrypt_with_add_data, \
	}


/**
 * Initialize a static instance for running AES-GCM operations using OpenSSL.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for AES operations.
 */
#define	aes_gcm_openssl_static_init(state_ptr)	{ \
		.base = AES_GCM_OPENSSL_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_GCM_OPENSSL_STATIC_H_ */
