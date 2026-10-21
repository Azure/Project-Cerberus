// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_WITH_PADDING_H_
#define AES_KEY_WRAP_WITH_PADDING_H_

#include "aes_key_wrap.h"
#include "crypto/aes_ecb.h"


/**
 * AES key wrap implementation based on RFC 5649.  Wrapped data has no restrictions on alignment or
 * length, except that more than 2^32 wrapped bytes cannot be supported.
 *
 * This provides a common implementation that is compatible with any instance of the AES-ECB
 * interface.
 */
struct aes_key_wrap_with_padding {
	struct aes_key_wrap base;	/**< Base key wrapping API. */
};


int aes_key_wrap_with_padding_init (struct aes_key_wrap_with_padding *aes_kwp,
	const struct aes_ecb_engine *ecb);
void aes_key_wrap_with_padding_release (const struct aes_key_wrap_with_padding *aes_kwp);


#endif	/* AES_KEY_WRAP_WITH_PADDING_H_ */
