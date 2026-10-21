// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_MANAGER_FLASH_STATIC_H_
#define CFM_MANAGER_FLASH_STATIC_H_

#include "cfm_manager_flash.h"
#include "cfm_manager_static.h"
#include "manifest/manifest_manager_flash_static.h"
#include "system/system_state_manager.h"


/* Internal functions declared to allow for static initialization. */
int cfm_manager_flash_activate_pending_manifest (const struct manifest_manager *manager);
int cfm_manager_flash_clear_pending_region (const struct manifest_manager *manager,	size_t size);
int cfm_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length);
int cfm_manager_flash_verify_pending_manifest (const struct manifest_manager *manager);
int cfm_manager_flash_clear_all_manifests (const struct manifest_manager *manager);

void cfm_manager_flash_free_cfm (const struct cfm_manager *manager, const struct cfm *cfm);
const struct cfm* cfm_manager_flash_get_active_cfm (const struct cfm_manager *manager);
const struct cfm* cfm_manager_flash_get_pending_cfm (const struct cfm_manager *manager);


/**
 * Initialize a static instance of a manager for handling CFMs.
 *
 * There is no validation done on the arguments.
 *
 * @param manager_ptr The CFM manager to initialize.
 * @param state_ptr Variable context for the CFM manager.
 * @param cfm_region1_ptr The CFM instance for the first flash region that can hold a CFM.
 * This region does not need to have a valid CFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param cfm_region2_ptr The CFM instance for the second flash region that can hold a CFM.
 * This region does not need to have a valid CFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state_mgr_ptr The state information for CFM management.
 * @param hash_ptr The hash engine to be used for CFM validation.
 * @param verification_ptr The module to be used for CFM verification.
 */
#define	cfm_manager_flash_static_init(manager_ptr, state_ptr, cfm_region1_ptr, cfm_region2_ptr, \
	state_mgr_ptr, hash_ptr, verification_ptr)	{ \
		.base = cfm_manager_static_init (&(state_ptr)->base, hash_ptr, 0, \
			cfm_manager_flash_activate_pending_manifest, cfm_manager_flash_clear_pending_region, \
			cfm_manager_flash_write_pending_data, cfm_manager_flash_verify_pending_manifest, \
			cfm_manager_flash_clear_all_manifests, cfm_manager_flash_get_active_cfm, \
			cfm_manager_flash_get_pending_cfm, cfm_manager_flash_free_cfm), \
		.manifest_manager = manifest_manager_flash_static_init (&(state_ptr)->flash_state, \
			&(manager_ptr)->base.base, &(cfm_region1_ptr)->base.base, \
			&(cfm_region2_ptr)->base.base, &(cfm_region1_ptr)->base_flash, \
			&(cfm_region2_ptr)->base_flash, state_mgr_ptr, hash_ptr, verification_ptr, \
			SYSTEM_STATE_MANIFEST_CFM, false, NULL), \
	}


#endif	/* CFM_MANAGER_FLASH_STATIC_H_ */
