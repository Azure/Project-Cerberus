// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_MOCK_H_
#define HOST_FLASH_MANAGER_MOCK_H_

#include "host_fw/host_flash_manager.h"
#include "mock.h"


/**
 * A mock for the manager of protected host flash.
 */
struct host_flash_manager_mock {
	struct host_flash_manager base;		/**< The base manager instance. */
	struct mock mock;					/**< The base mock interface. */
};


int host_flash_manager_mock_init (struct host_flash_manager_mock *mock);
void host_flash_manager_mock_release (struct host_flash_manager_mock *mock);

int host_flash_manager_mock_validate_and_release (struct host_flash_manager_mock *mock);


#endif /* HOST_FLASH_MANAGER_MOCK_H_ */
