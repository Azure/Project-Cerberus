// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_FLASH_STATIC_H_
#define PCD_MANAGER_FLASH_STATIC_H_

#include "pcd_manager_flash.h"
#include "pcd_manager_static.h"
#include "manifest/manifest_manager_flash_static.h"
#include "system/system_state_manager.h"


/* Internal functions declared to allow for static initialization. */
int pcd_manager_flash_activate_pending_manifest (const struct manifest_manager *manager);
int pcd_manager_flash_clear_pending_region (const struct manifest_manager *manager,	size_t size);
int pcd_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length);
int pcd_manager_flash_verify_pending_manifest (const struct manifest_manager *manager);
int pcd_manager_flash_clear_all_manifests (const struct manifest_manager *manager);

void pcd_manager_flash_free_pcd (const struct pcd_manager *manager, const struct pcd *pcd);
const struct pcd* pcd_manager_flash_get_active_pcd (const struct pcd_manager *manager);


/**
 * Initialize a static instance of a manager for handling PCDs.
 *
 * There is no validation done on the arguments.
 *
 * @param manager_ptr The PCD manager to initialize.
 * @param state_ptr Variable context for the PCD manager.
 * @param pcd_region1_ptr The PCD instance for the first flash region that can hold a PCD.
 * This region does not need to have a valid PCD. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pcd_region2_ptr The PCD instance for the second flash region that can hold a PCD.
 * This region does not need to have a valid PCD. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state_mgr_ptr The state information for PCD management.
 * @param hash_ptr The hash engine to be used for PCD validation.
 * @param verification_ptr The module to be used for PCD verification.
 */
#define	pcd_manager_flash_static_init(manager_ptr, state_ptr, pcd_region1_ptr, pcd_region2_ptr, \
	state_mgr_ptr, hash_ptr, verification_ptr)	{ \
		.base = pcd_manager_static_init (&(state_ptr)->base, hash_ptr, 0, \
			pcd_manager_flash_activate_pending_manifest, pcd_manager_flash_clear_pending_region, \
			pcd_manager_flash_write_pending_data, pcd_manager_flash_verify_pending_manifest, \
			pcd_manager_flash_clear_all_manifests, pcd_manager_flash_get_active_pcd, \
			pcd_manager_flash_free_pcd), \
		.manifest_manager = manifest_manager_flash_static_init (&(state_ptr)->flash_state, \
			&(manager_ptr)->base.base, &(pcd_region1_ptr)->base.base, \
			&(pcd_region2_ptr)->base.base, &(pcd_region1_ptr)->base_flash, \
			&(pcd_region2_ptr)->base_flash, state_mgr_ptr, hash_ptr, verification_ptr, \
			SYSTEM_STATE_MANIFEST_PCD, true, NULL), \
	}


#endif	/* PCD_MANAGER_FLASH_STATIC_H_ */
