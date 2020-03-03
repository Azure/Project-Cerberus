// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_FLASH_H_
#define CFM_MANAGER_FLASH_H_

#include <stdbool.h>
#include "cfm_manager.h"
#include "cfm_flash.h"
#include "manifest/manifest_manager_flash.h"


/**
 * A manager for a single set of CFMs stored in flash.
 */
struct cfm_manager_flash {
	struct cfm_manager base;						/**< The base CFM manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
};


int cfm_manager_flash_init (struct cfm_manager_flash *manager, struct cfm_flash *cfm_region1,
	struct cfm_flash *cfm_region2, struct state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification);
void cfm_manager_flash_release (struct cfm_manager_flash *manager);


#endif /* CFM_MANAGER_FLASH_H_ */
