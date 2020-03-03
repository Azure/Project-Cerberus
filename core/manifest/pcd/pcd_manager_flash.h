// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_FLASH_H_
#define PCD_MANAGER_FLASH_H_

#include <stdbool.h>
#include "pcd_manager.h"
#include "pcd_flash.h"
#include "manifest/manifest_manager_flash.h"


/**
 * A manager for a single set of PCDs stored in flash.
 */
struct pcd_manager_flash {
	struct pcd_manager base;						/**< The base PCD manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
};


int pcd_manager_flash_init (struct pcd_manager_flash *manager, struct pcd_flash *pcd_region1,
	struct pcd_flash *pcd_region2, struct state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification);
void pcd_manager_flash_release (struct pcd_manager_flash *manager);


#endif /* PCD_MANAGER_FLASH_H_ */
