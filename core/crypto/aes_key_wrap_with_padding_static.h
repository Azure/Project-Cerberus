// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_WITH_PADDING_STATIC_H_
#define AES_KEY_WRAP_WITH_PADDING_STATIC_H_

#include "aes_key_wrap_static.h"
#include "aes_key_wrap_with_padding.h"


/* Internal functions declared to allow for static initialization. */
int aes_key_wrap_with_padding_wrap (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *data, size_t length, uint8_t *wrapped, size_t out_length);
int aes_key_wrap_with_padding_unwrap (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *wrapped, size_t length, uint8_t *data, size_t *out_length);


/**
 * Constant initializer for the AES key wrap API.
 */
#define	AES_KEY_WRAP_WITH_PADDING_API_INIT { \
		.set_kek = aes_key_wrap_set_kek, \
		.clear_kek = aes_key_wrap_clear_kek, \
		.wrap = aes_key_wrap_with_padding_wrap, \
		.unwrap = aes_key_wrap_with_padding_unwrap, \
	}


/**
 * Initialize a static instance for encrypting data using the AES Key Wrap algorithm from RFC 3394.
 *
 * There is no validation done on the arguments.
 *
 * @param ecb_ptr AES engine to use for encrypting the data.
 */
#define	aes_key_wrap_with_padding_static_init(ecb_ptr) { \
		.base = aes_key_wrap_static_init_internal (AES_KEY_WRAP_WITH_PADDING_API_INIT, ecb_ptr), \
	}


#endif	/* AES_KEY_WRAP_WITH_PADDING_STATIC_H_ */
