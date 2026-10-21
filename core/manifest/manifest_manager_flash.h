// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_FLASH_H_
#define MANIFEST_MANAGER_FLASH_H_

#include <stdbool.h>
#include <stdint.h>
#include "manifest.h"
#include "manifest_flash.h"
#include "manifest_manager.h"
#include "platform_api.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "flash/flash.h"
#include "flash/flash_updater.h"
#include "state_manager/state_manager.h"


/**
 * Variable context for a single manifest flash region.
 */
struct manifest_manager_flash_region_state {
	int ref_count;					/**< The number of active references to the manifest region. */
	bool is_valid;					/**< Flag indicating if the region has a valid manifest. */
	struct flash_updater updater;	/**< Update manager for the flash region. */
};

/**
 * Variable context for managing a single set of manifests on flash.
 */
struct manifest_manager_flash_state {
	platform_mutex lock;								/**< Synchronization for flash manager state. */
	struct flash_updater *updating;						/**< The update manager being used to write new manifest data. */
	struct manifest_manager_flash_region_state region1;	/**< Context for the first flash region. */
	struct manifest_manager_flash_region_state region2;	/**< Context for the second flash region. */
};

/**
 * Container of information for each managed manifest region on flash.
 */
struct manifest_manager_flash_region {
	struct manifest_manager_flash_region_state *state;	/**< Variable context for the manifest region. */
	const struct manifest *manifest;					/**< The manifest instance for the flash region. */
	const struct manifest_flash *flash;					/**< The flash parser for the manifest. */
};

/**
 * A manager for a single set of manifests stored in flash.
 *
 * This is not an implementation of the API for managing manifests.  This is an internal helper type
 * for managing manifests on flash.
 */
struct manifest_manager_flash {
	struct manifest_manager_flash_state *state;			/**< Variable context for manifest management on flash. */
	const struct manifest_manager *base;				/**< Reference to the base manager instance. */
	const struct state_manager *state_mgr;				/**< State manager interface. */
	const struct hash_engine *hash;						/**< The hash engine for manifest validation. */
	const struct signature_verification *verification;	/**< Verification module for verifying manifest signatures. */
	struct manifest_manager_flash_region region1;		/**< The first flash region for a manifest. */
	struct manifest_manager_flash_region region2;		/**< The second flash region for a manifest. */
	uint8_t manifest_index;								/**< Index of manifest in state manager. */
	bool sku_upgrade_permitted;							/**< Manifest permitted to upgrade from generic to SKU-specific */

	/**
	 * Function called after standard manifest verification has been completed successfully.  This
	 * can be null to skip calling this function.
	 *
	 * @param manager The manager running verification.
	 *
	 * @return 0 if verification should complete successfully or an error code.
	 */
	int (*post_verify) (const struct manifest_manager_flash *manager);
};


int manifest_manager_flash_init (struct manifest_manager_flash *manager,
	struct manifest_manager_flash_state *state, const struct manifest_manager *base,
	const struct manifest *region1, const struct manifest *region2,
	const struct manifest_flash *region1_flash, const struct manifest_flash *region2_flash,
	const struct state_manager *state_mgr, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t manifest_index,
	uint8_t log_msg_empty, bool sku_upgrade_permitted);
int manifest_manager_flash_init_state (const struct manifest_manager_flash *manager,
	uint8_t log_msg_empty);
void manifest_manager_flash_release (const struct manifest_manager_flash *manager);

const struct manifest_manager_flash_region* manifest_manager_flash_get_region (
	const struct manifest_manager_flash *manager, bool active);
const struct manifest_manager_flash_region* manifest_manager_flash_get_manifest_region (
	const struct manifest_manager_flash *manager, bool active);


void manifest_manager_flash_free_manifest (const struct manifest_manager_flash *manager,
	const struct manifest *manifest);

int manifest_manager_flash_activate_pending_manifest (const struct manifest_manager_flash *manager);
int manifest_manager_flash_clear_pending_region (const struct manifest_manager_flash *manager,
	size_t size);
int manifest_manager_flash_write_pending_data (const struct manifest_manager_flash *manager,
	const uint8_t *data, size_t length);
int manifest_manager_flash_verify_pending_manifest (const struct manifest_manager_flash *manager);
int manifest_manager_flash_clear_all_manifests (const struct manifest_manager_flash *manager,
	bool no_lock);


#endif	/* MANIFEST_MANAGER_FLASH_H_ */
