// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_XTS_OPENSSL_STATIC_H_
#define AES_XTS_OPENSSL_STATIC_H_

#include "aes_xts_openssl.h"


/* Internal functions declared to allow for static initialization. */
int aes_xts_openssl_set_key (const struct aes_xts_engine *engine, const uint8_t *key,
	size_t length);
int aes_xts_openssl_encrypt_data (const struct aes_xts_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t data_unit_id[16], uint8_t *ciphertext, size_t out_length);
int aes_xts_openssl_decrypt_data (const struct aes_xts_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t data_unit_id[16], uint8_t *plaintext, size_t out_length);


/**
 * Constant initializer for the AES-XTS API.
 */
#define	AES_XTS_OPENSSL_API_INIT	{ \
		.set_key = aes_xts_openssl_set_key, \
		.encrypt_data = aes_xts_openssl_encrypt_data, \
		.decrypt_data = aes_xts_openssl_decrypt_data, \
	}


/**
 * Initialize a static instance for running AES-XTS operations using OpenSSL.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for AES operations.
 */
#define	aes_xts_openssl_static_init(state_ptr)	{ \
		.base = AES_XTS_OPENSSL_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* AES_XTS_OPENSSL_STATIC_H_ */
