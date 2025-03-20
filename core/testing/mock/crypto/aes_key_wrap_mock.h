// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_MOCK_H_
#define AES_KEY_WRAP_MOCK_H_

#include "mock.h"
#include "crypto/aes_key_wrap_interface.h"


/**
 * A mock for AES key wrap/unwrap.
 */
struct aes_key_wrap_mock {
	struct aes_key_wrap_interface base;	/**< The base AES key wrap API instance. */
	struct mock mock;					/**< The base mock interface. */
};


int aes_key_wrap_mock_init (struct aes_key_wrap_mock *mock);
void aes_key_wrap_mock_release (struct aes_key_wrap_mock *mock);

int aes_key_wrap_mock_validate_and_release (struct aes_key_wrap_mock *mock);


#endif	/* AES_KEY_WRAP_MOCK_H_ */
