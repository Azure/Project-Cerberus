// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_MANAGER_FLASH_H_
#define PFM_MANAGER_FLASH_H_

#include <stdbool.h>
#include "pfm_manager.h"
#include "pfm_flash.h"
#include "manifest/manifest_manager_flash.h"
#include "host_fw/host_state_manager.h"


/**
 * A manager for a single set of PFMs stored in flash.
 */
struct pfm_manager_flash {
	struct pfm_manager base;						/**< The base PFM manager instance. */
	struct manifest_manager_flash manifest_manager;	/**< Common manifest manager flash members. */
	struct host_state_manager *host_state;			/**< Manager for host state. */
};


int pfm_manager_flash_init (struct pfm_manager_flash *manager, struct pfm_flash *pfm_region1,
	struct pfm_flash *pfm_region2, struct host_state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification);
int pfm_manager_flash_init_port (struct pfm_manager_flash *manager, struct pfm_flash *pfm_region1,
	struct pfm_flash *pfm_region2, struct host_state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification, int port);
void pfm_manager_flash_release (struct pfm_manager_flash *manager);

/* Internal functions for use by derived types. */
int pfm_manager_flash_verify_pending_pfm (struct manifest_manager *manager);


#endif /* PFM_MANAGER_FLASH_H_ */
