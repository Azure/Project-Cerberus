// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MANAGER_FLASH_STATIC_H_
#define PFM_MANAGER_FLASH_STATIC_H_

#include "pfm_manager_flash.h"
#include "pfm_manager_static.h"
#include "manifest/manifest_manager_flash_static.h"


/* Internal functions declared to allow for static initialization. */
int pfm_manager_flash_activate_pending_manifest (const struct manifest_manager *manager);
int pfm_manager_flash_clear_pending_region (const struct manifest_manager *manager,	size_t size);
int pfm_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length);
int pfm_manager_flash_clear_all_manifests (const struct manifest_manager *manager);

void pfm_manager_flash_free_pfm (const struct pfm_manager *manager, const struct pfm *pfm);
const struct pfm* pfm_manager_flash_get_active_pfm (const struct pfm_manager *manager);
const struct pfm* pfm_manager_flash_get_pending_pfm (const struct pfm_manager *manager);


/**
 * Initialize a static instance of a manager for handling PFMs.
 *
 * There is no validation done on the arguments.
 *
 * @param manager_ptr The PFM manager to initialize.
 * @param state_ptr Variable context for the PFM manager.
 * @param pfm_region1_ptr The PFM instance for the first flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pfm_region2_ptr The PFM instance for the second flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state_mgr_ptr The state information for PFM management.
 * @param hash_ptr The hash engine to be used for PFM validation.
 * @param verification_ptr The module to be used for PFM verification.
 * @param port_arg The port identifier to set.
 */
#define	pfm_manager_flash_static_init(manager_ptr, state_ptr, pfm_region1_ptr, pfm_region2_ptr, \
	state_mgr_ptr, hash_ptr, verification_ptr, port_arg)	{ \
		.base = pfm_manager_static_init (&(state_ptr)->base, hash_ptr, port_arg, \
			pfm_manager_flash_activate_pending_manifest, pfm_manager_flash_clear_pending_region, \
			pfm_manager_flash_write_pending_data, pfm_manager_flash_verify_pending_manifest, \
			pfm_manager_flash_clear_all_manifests, pfm_manager_flash_get_active_pfm, \
			pfm_manager_flash_get_pending_pfm, pfm_manager_flash_free_pfm), \
		.manifest_manager = manifest_manager_flash_static_init (&(state_ptr)->flash_state, \
			&(manager_ptr)->base.base, &(pfm_region1_ptr)->base.base, \
			&(pfm_region2_ptr)->base.base, &(pfm_region1_ptr)->base_flash, \
			&(pfm_region2_ptr)->base_flash, &(state_mgr_ptr)->base, hash_ptr, verification_ptr, 0, \
			false, NULL), \
		.host_state = state_mgr_ptr, \
	}


#endif	/* PFM_MANAGER_FLASH_STATIC_H_ */
