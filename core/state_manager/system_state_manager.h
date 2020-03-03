// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_STATE_MANAGER_H_
#define SYSTEM_STATE_MANAGER_H_

#include <stdint.h>
#include <stdbool.h>
#include "flash/flash.h"
#include "state_manager/state_manager.h"


/**
 * Manifest types supported by system state manager.
 */
enum {
	SYSTEM_STATE_MANIFEST_CFM = 0,		/**< CFM manifest. */
	SYSTEM_STATE_MANIFEST_PCD,			/**< PCD manifest. */
	NUM_SYSTEM_STATE_MANIFESTS			/**< Total number of system state manager manifest types. */
};


int system_state_manager_init (struct state_manager *manager, struct flash *state_flash,
	uint32_t store_addr);
void system_state_manager_release (struct state_manager *manager);


#endif /* SYSTEM_STATE_MANAGER_H_ */
