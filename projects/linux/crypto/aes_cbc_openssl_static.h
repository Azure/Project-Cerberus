// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_CBC_OPENSSL_STATIC_H_
#define AES_CBC_OPENSSL_STATIC_H_

#include "aes_cbc_openssl.h"


/* Internal functions declared to allow for static initialization. */
int aes_cbc_openssl_set_key (const struct aes_cbc_engine *engine, const uint8_t *key,
	size_t length);
int aes_cbc_openssl_encrypt_data (const struct aes_cbc_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *ciphertext, size_t out_length,
	uint8_t out_iv[AES_CBC_BLOCK_SIZE]);
int aes_cbc_openssl_decrypt_data (const struct aes_cbc_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *plaintext, size_t out_length,
	uint8_t out_iv[AES_CBC_BLOCK_SIZE]);


/**
 * Constant initializer for the AES-CBC API.
 */
#define	AES_CBC_OPENSSL_API_INIT	{ \
		.set_key = aes_cbc_openssl_set_key, \
		.encrypt_data = aes_cbc_openssl_encrypt_data, \
		.decrypt_data = aes_cbc_openssl_decrypt_data, \
	}


/**
 * Initialize a static instance for running AES-CBC operations using OpenSSL.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for AES operations.
 */
#define	aes_cbc_openssl_static_init(state_ptr)	{ \
		.base = AES_CBC_OPENSSL_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_CBC_OPENSSL_STATIC_H_ */
