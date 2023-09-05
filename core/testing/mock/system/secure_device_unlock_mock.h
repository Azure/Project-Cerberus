// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_MOCK_H_
#define SECURE_DEVICE_UNLOCK_MOCK_H_

#include "system/secure_device_unlock.h"
#include "mock.h"


/**
 * A mock for a secure unlock handler.
 */
struct secure_device_unlock_mock {
	struct secure_device_unlock base;		/**< The base handler instance. */
	struct mock mock;						/**< The base mock interface. */
};


int secure_device_unlock_mock_init (struct secure_device_unlock_mock *mock);
void secure_device_unlock_mock_release (struct secure_device_unlock_mock *mock);

int secure_device_unlock_mock_validate_and_release (struct secure_device_unlock_mock *mock);


#endif /* SECURE_DEVICE_UNLOCK_MOCK_H_ */
