// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_XTS_MOCK_H_
#define AES_XTS_MOCK_H_

#include "mock.h"
#include "crypto/aes_xts.h"


/**
 * A mock for the AES-XTS API.
 */
struct aes_xts_engine_mock {
	struct aes_xts_engine base;	/**< The base AES-XTS API instance. */
	struct mock mock;			/**< The base mock interface. */
};


int aes_xts_mock_init (struct aes_xts_engine_mock *mock);
void aes_xts_mock_release (struct aes_xts_engine_mock *mock);

int aes_xts_mock_validate_and_release (struct aes_xts_engine_mock *mock);


#endif	/* AES_XTS_MOCK_H_ */
