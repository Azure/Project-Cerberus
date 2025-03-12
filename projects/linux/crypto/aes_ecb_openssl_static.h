// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_ECB_OPENSSL_STATIC_H_
#define AES_ECB_OPENSSL_STATIC_H_

#include "aes_ecb_openssl.h"


/* Internal functions declared to allow for static initialization. */
int aes_ecb_openssl_set_key (const struct aes_ecb_engine *engine, const uint8_t *key,
	size_t length);
int aes_ecb_openssl_encrypt_data (const struct aes_ecb_engine *engine, const uint8_t *plaintext,
	size_t length, uint8_t *ciphertext, size_t out_length);
int aes_ecb_openssl_decrypt_data (const struct aes_ecb_engine *engine, const uint8_t *ciphertext,
	size_t length, uint8_t *plaintext, size_t out_length);


/**
 * Constant initializer for the AES-ECB API.
 */
#define	AES_ECB_OPENSSL_API_INIT	{ \
		.set_key = aes_ecb_openssl_set_key, \
		.encrypt_data = aes_ecb_openssl_encrypt_data, \
		.decrypt_data = aes_ecb_openssl_decrypt_data, \
	}


/**
 * Initialize a static instance for running AES-ECB operations using OpenSSL.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for AES operations.
 */
#define	aes_ecb_openssl_static_init(state_ptr)	{ \
		.base = AES_ECB_OPENSSL_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_ECB_OPENSSL_STATIC_H_ */
