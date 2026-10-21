// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_CBC_MOCK_H_
#define AES_CBC_MOCK_H_

#include "mock.h"
#include "crypto/aes_cbc.h"


/**
 * A mock for the AES-CBC API.
 */
struct aes_cbc_engine_mock {
	struct aes_cbc_engine base;	/**< The base AES-CBC API instance. */
	struct mock mock;			/**< The base mock interface. */
};


int aes_cbc_mock_init (struct aes_cbc_engine_mock *mock);
void aes_cbc_mock_release (struct aes_cbc_engine_mock *mock);

int aes_cbc_mock_validate_and_release (struct aes_cbc_engine_mock *mock);


#endif	/* AES_CBC_MOCK_H_ */
