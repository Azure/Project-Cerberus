// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_MOCK_H_
#define AES_MOCK_H_

#include "mock.h"
#include "crypto/aes.h"


/**
 * A mock for the AES-GCM API.
 */
struct aes_engine_mock {
	struct aes_engine base;	/**< The base AES-GCM API instance. */
	struct mock mock;		/**< The base mock interface. */
};


int aes_mock_init (struct aes_engine_mock *mock);
void aes_mock_release (struct aes_engine_mock *mock);

int aes_mock_validate_and_release (struct aes_engine_mock *mock);


#endif	/* AES_MOCK_H_ */
