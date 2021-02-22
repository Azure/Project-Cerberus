// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_DUAL_MOCK_H_
#define HOST_FLASH_MANAGER_DUAL_MOCK_H_

#include "host_fw/host_flash_manager_dual.h"
#include "mock.h"


/**
 * A mock for the manager of protected host flash using dual flashes.
 */
struct host_flash_manager_dual_mock {
	struct host_flash_manager_dual base;	/**< The base manager instance. */
	struct mock mock;						/**< The base mock interface. */
};


int host_flash_manager_dual_mock_init (struct host_flash_manager_dual_mock *mock);
void host_flash_manager_dual_mock_release (struct host_flash_manager_dual_mock *mock);

int host_flash_manager_dual_mock_validate_and_release (struct host_flash_manager_dual_mock *mock);


#endif /* HOST_FLASH_MANAGER_DUAL_MOCK_H_ */
