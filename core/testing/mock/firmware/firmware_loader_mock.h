// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_LOADER_MOCK_H_
#define FIRMWARE_LOADER_MOCK_H_

#include "firmware/firmware_loader.h"
#include "mock.h"


/**
 * A mock for a handler for loading firmware images.
 */
struct firmware_loader_mock {
	struct firmware_loader base;	/**< The base loader instance. */
	struct mock mock;				/**< The base mock interface. */
};


int firmware_loader_mock_init (struct firmware_loader_mock *mock);
void firmware_loader_mock_release (struct firmware_loader_mock *mock);

int firmware_loader_mock_validate_and_release (struct firmware_loader_mock *mock);


#endif /* FIRMWARE_LOADER_MOCK_H_ */
