// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_STORE_MOCK_H_
#define FLASH_STORE_MOCK_H_

#include "flash/flash_store.h"
#include "mock.h"


/**
 * A mock for flash block storage API.
 */
struct flash_store_mock {
	struct flash_store base;		/**< The base flash storage API instance. */
	struct mock mock;				/**< The base mock interface. */
};


int flash_store_mock_init (struct flash_store_mock *mock);
void flash_store_mock_release (struct flash_store_mock *mock);

int flash_store_mock_validate_and_release (struct flash_store_mock *mock);


#endif /* FLASH_STORE_MOCK_H_ */
