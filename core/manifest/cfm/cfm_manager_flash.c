// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_manager_flash.h"
#include "manifest/manifest_logging.h"
#include "system/system_state_manager.h"


static struct cfm* cfm_manager_flash_get_cfm (struct cfm_manager_flash *manager, bool active)
{
	struct cfm_flash *flash;
	struct manifest_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	region = manifest_manager_flash_get_manifest_region (&manager->manifest_manager, active);
	if (region == NULL) {
		return NULL;
	}

	flash = (struct cfm_flash*) region->manifest;
	return &flash->base;
}

static struct cfm* cfm_manager_flash_get_active_cfm (struct cfm_manager *manager)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;

	return cfm_manager_flash_get_cfm (cfm_mgr, true);
}

static struct cfm* cfm_manager_flash_get_pending_cfm (struct cfm_manager *manager)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;

	return cfm_manager_flash_get_cfm (cfm_mgr, false);
}

static void cfm_manager_flash_free_cfm (struct cfm_manager *manager, struct cfm *cfm)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return;
	}

	manifest_manager_flash_free_manifest (&cfm_mgr->manifest_manager, (struct manifest*) cfm);
}

static int cfm_manager_flash_activate_pending_cfm (struct manifest_manager *manager)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;
	int status;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_activate_pending_manifest (&cfm_mgr->manifest_manager);
	if (status == 0) {
		cfm_manager_on_cfm_activated (&cfm_mgr->base);
	}

	return status;
}

static int cfm_manager_flash_clear_pending_region (struct manifest_manager *manager, size_t size)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_clear_pending_region (&cfm_mgr->manifest_manager, size);
}

static int cfm_manager_flash_write_pending_data (struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_write_pending_data (&cfm_mgr->manifest_manager, data, length);
}

static int cfm_manager_flash_verify_pending_cfm (struct manifest_manager *manager)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;
	int status;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_verify_pending_manifest (&cfm_mgr->manifest_manager);
	if (status == 0) {
		cfm_manager_on_cfm_verified (&cfm_mgr->base);
	}

	return status;
}

static int cfm_manager_flash_clear_all_manifests (struct manifest_manager *manager)
{
	struct cfm_manager_flash *cfm_mgr = (struct cfm_manager_flash*) manager;
	int status;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_clear_all_manifests (&cfm_mgr->manifest_manager, false);
	if (status == 0) {
		cfm_manager_on_clear_active (&cfm_mgr->base);
	}

	return status;
}

/**
 * Initialize the manager for handling CFMs.
 *
 * @param manager The CFM manager to initialize.
 * @param cfm_region1 The CFM instance for the first flash region that can hold a CFM.
 * This region does not need to have a valid CFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param cfm_region2 The CFM instance for the second flash region that can hold a CFM.
 * This region does not need to have a valid CFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state The state information for CFM management.
 * @param hash The hash engine to be used for CFM validation.
 * @param verification The module to be used for CFM verification.
 *
 * @return 0 if the cfm manager was successfully initialized or an error code.
 */
int cfm_manager_flash_init (struct cfm_manager_flash *manager, struct cfm_flash *cfm_region1,
	struct cfm_flash *cfm_region2, struct state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification)
{
	int status;

	if ((manager == NULL) || (cfm_region1 == NULL) || (cfm_region2 == NULL) || (state == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct cfm_manager_flash));

	status = cfm_manager_init (&manager->base, hash);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init (&manager->manifest_manager, &manager->base.base,
		&cfm_region1->base.base, &cfm_region2->base.base, &cfm_region1->base_flash,
		&cfm_region2->base_flash, state, hash, verification, SYSTEM_STATE_MANIFEST_CFM,
		MANIFEST_LOGGING_EMPTY_CFM, false);
	if (status != 0) {
		cfm_manager_release (&manager->base);
		return status;
	}

	manager->base.get_active_cfm = cfm_manager_flash_get_active_cfm;
	manager->base.get_pending_cfm = cfm_manager_flash_get_pending_cfm;
	manager->base.free_cfm = cfm_manager_flash_free_cfm;

	manager->base.base.activate_pending_manifest = cfm_manager_flash_activate_pending_cfm;
	manager->base.base.clear_pending_region = cfm_manager_flash_clear_pending_region;
	manager->base.base.write_pending_data = cfm_manager_flash_write_pending_data;
	manager->base.base.verify_pending_manifest = cfm_manager_flash_verify_pending_cfm;
	manager->base.base.clear_all_manifests = cfm_manager_flash_clear_all_manifests;

	return 0;
}

/**
 * Release the resources used by a manager of CFMs in flash.
 *
 * @param manager The CFM manager to release.
 */
void cfm_manager_flash_release (struct cfm_manager_flash *manager)
{
	if (manager != NULL) {
		cfm_manager_release (&manager->base);
		manifest_manager_flash_release (&manager->manifest_manager);
	}
}
