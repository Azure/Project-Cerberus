// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef KEYSTORE_MOCK_H_
#define KEYSTORE_MOCK_H_

#include "keystore/keystore.h"
#include "mock.h"


/**
 * Mock for storage of device keys.
 */
struct keystore_mock {
	struct keystore base;		/**< The keystore instance. */
	struct mock mock;			/**< The base mock interface. */
};


int keystore_mock_init (struct keystore_mock *mock);
void keystore_mock_release (struct keystore_mock *mock);

int keystore_mock_validate_and_release (struct keystore_mock *mock);


#endif /* KEYSTORE_MOCK_H_ */
