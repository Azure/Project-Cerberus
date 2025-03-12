// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_ECB_MOCK_H_
#define AES_ECB_MOCK_H_

#include "mock.h"
#include "crypto/aes_ecb.h"


/**
 * A mock for the AES-ECB API.
 */
struct aes_ecb_engine_mock {
	struct aes_ecb_engine base;	/**< The base AES-ECB API instance. */
	struct mock mock;			/**< The base mock interface. */
};


int aes_ecb_mock_init (struct aes_ecb_engine_mock *mock);
void aes_ecb_mock_release (struct aes_ecb_engine_mock *mock);

int aes_ecb_mock_validate_and_release (struct aes_ecb_engine_mock *mock);


#endif	/* AES_ECB_MOCK_H_ */
