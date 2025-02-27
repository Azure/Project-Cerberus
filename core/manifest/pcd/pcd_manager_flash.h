// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_FLASH_H_
#define PCD_MANAGER_FLASH_H_

#include <stdbool.h>
#include "pcd_flash.h"
#include "pcd_manager.h"
#include "manifest/manifest_manager_flash.h"


/**
 * Variable context for the manager of a set of PCDs in flash.
 */
struct pcd_manager_flash_state {
	struct pcd_manager_state base;						/**< Base state information for PCD management. */
	struct manifest_manager_flash_state flash_state;	/**< Context for common flash manifest management. */
};

/**
 * A manager for a single set of PCDs stored in flash.
 */
struct pcd_manager_flash {
	struct pcd_manager base;						/**< The base PCD manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
};


int pcd_manager_flash_init (struct pcd_manager_flash *manager,
	struct pcd_manager_flash_state *state, const struct pcd_flash *pcd_region1,
	const struct pcd_flash *pcd_region2, struct state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification);
int pcd_manager_flash_init_state (const struct pcd_manager_flash *manager);
void pcd_manager_flash_release (const struct pcd_manager_flash *manager);


#endif	/* PCD_MANAGER_FLASH_H_ */
