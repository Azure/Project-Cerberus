// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_H_
#define AES_KEY_WRAP_H_

#include "aes_ecb.h"
#include "aes_key_wrap_interface.h"


/**
 * AES key wrap implementation based on RFC 3394.  Wrapped data must be 8-byte (64 bits) aligned and
 * must be at least 16 bytes.
 *
 * This provides a common implementation that is compatible with any instance of the AES-ECB
 * interface.
 */
struct aes_key_wrap {
	struct aes_key_wrap_interface base;	/**< Base key wrapping API. */
	const struct aes_ecb_engine *ecb;	/**< AES engine to use for encrypt/decrypt operations. */
};


int aes_key_wrap_init (struct aes_key_wrap *aes_kw, const struct aes_ecb_engine *ecb);
void aes_key_wrap_release (const struct aes_key_wrap *aes_kw);

/* Internal functions for use by derived types. */
int aes_key_wrap_set_kek (const struct aes_key_wrap_interface *aes_kw, const uint8_t *kek,
	size_t length);
int aes_key_wrap_clear_kek (const struct aes_key_wrap_interface *aes_kw);

int aes_key_wrap_data_wrap (const struct aes_key_wrap *key_wrap,
	const uint8_t initial_value[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE], uint8_t *wrapped,
	size_t length);
int aes_key_wrap_data_unwrap (const struct aes_key_wrap *key_wrap, const uint8_t *wrapped,
	size_t length, uint8_t *data, size_t out_length,
	uint8_t integrity_check[AES_KEY_WRAP_INTERFACE_BLOCK_SIZE]);


#endif	/* AES_KEY_WRAP_H_ */
