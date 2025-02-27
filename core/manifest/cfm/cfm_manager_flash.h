// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_FLASH_H_
#define CFM_MANAGER_FLASH_H_

#include <stdbool.h>
#include "cfm_flash.h"
#include "cfm_manager.h"
#include "manifest/manifest_manager_flash.h"


/**
 * Variable context for the manager of a set of CFMs in flash.
 */
struct cfm_manager_flash_state {
	struct cfm_manager_state base;						/**< Base state information for CFM management. */
	struct manifest_manager_flash_state flash_state;	/**< Context for common flash manifest management. */
};

/**
 * A manager for a single set of CFMs stored in flash.
 */
struct cfm_manager_flash {
	struct cfm_manager base;						/**< The base CFM manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
};


int cfm_manager_flash_init (struct cfm_manager_flash *manager,
	struct cfm_manager_flash_state *state, const struct cfm_flash *cfm_region1,
	const struct cfm_flash *cfm_region2, struct state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification);
int cfm_manager_flash_init_state (const struct cfm_manager_flash *manager);
void cfm_manager_flash_release (const struct cfm_manager_flash *manager);


#endif	/* CFM_MANAGER_FLASH_H_ */
