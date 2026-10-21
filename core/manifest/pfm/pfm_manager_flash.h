// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MANAGER_FLASH_H_
#define PFM_MANAGER_FLASH_H_

#include <stdbool.h>
#include "pfm_flash.h"
#include "pfm_manager.h"
#include "host_fw/host_state_manager.h"
#include "manifest/manifest_manager_flash.h"


/**
 * Variable context for the manager of a set of PFMs in flash.
 */
struct pfm_manager_flash_state {
	struct pfm_manager_state base;						/**< Base state information for PFM management. */
	struct manifest_manager_flash_state flash_state;	/**< Context for common flash manifest management. */
};

/**
 * A manager for a single set of PFMs stored in flash.
 */
struct pfm_manager_flash {
	struct pfm_manager base;						/**< The base PFM manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
	const struct host_state_manager *host_state;	/**< Manager for host state. */
};


int pfm_manager_flash_init (struct pfm_manager_flash *manager,
	struct pfm_manager_flash_state *state, const struct pfm_flash *pfm_region1,
	const struct pfm_flash *pfm_region2, const struct host_state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification);
int pfm_manager_flash_init_port (struct pfm_manager_flash *manager,
	struct pfm_manager_flash_state *state, const struct pfm_flash *pfm_region1,
	const struct pfm_flash *pfm_region2, const struct host_state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification, int port);
int pfm_manager_flash_init_state (const struct pfm_manager_flash *manager);
void pfm_manager_flash_release (const struct pfm_manager_flash *manager);

/* Internal functions for use by derived types. */
int pfm_manager_flash_verify_pending_manifest (const struct manifest_manager *manager);


#endif	/* PFM_MANAGER_FLASH_H_ */
