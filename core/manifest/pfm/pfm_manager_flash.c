// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_manager_flash.h"
#include "manifest/manifest_logging.h"
#include "host_fw/host_state_manager.h"


static struct pfm* pfm_manager_flash_get_pfm (struct pfm_manager_flash *manager,
	bool active)
{
	struct pfm_flash *flash;
	struct manifest_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	region = manifest_manager_flash_get_manifest_region (&manager->manifest_manager, active);
	if (region == NULL) {
		return NULL;
	}

	flash = (struct pfm_flash*) region->manifest;
	return &flash->base;
}

static struct pfm* pfm_manager_flash_get_active_pfm (struct pfm_manager *manager)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;

	return pfm_manager_flash_get_pfm (pfm_mgr, true);
}

static struct pfm* pfm_manager_flash_get_pending_pfm (struct pfm_manager *manager)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;

	return pfm_manager_flash_get_pfm (pfm_mgr, false);
}

static void pfm_manager_flash_free_pfm (struct pfm_manager *manager, struct pfm *pfm)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return;
	}

	manifest_manager_flash_free_manifest (&pfm_mgr->manifest_manager, (struct manifest*) pfm);
}

static int pfm_manager_flash_activate_pending_pfm (struct manifest_manager *manager)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;
	int status;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_activate_pending_manifest (&pfm_mgr->manifest_manager);
	if (status == 0) {
		host_state_manager_set_pfm_dirty (pfm_mgr->host_state, false);
		pfm_manager_on_pfm_activated (&pfm_mgr->base);
	}

	return status;
}

static int pfm_manager_flash_clear_pending_region (struct manifest_manager *manager, size_t size)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_clear_pending_region (&pfm_mgr->manifest_manager, size);
}

static int pfm_manager_flash_write_pending_data (struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_write_pending_data (&pfm_mgr->manifest_manager, data, length);
}

int pfm_manager_flash_verify_pending_pfm (struct manifest_manager *manager)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;
	int status;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_verify_pending_manifest (&pfm_mgr->manifest_manager);
	if (status == 0) {
		host_state_manager_set_pfm_dirty (pfm_mgr->host_state, true);
		pfm_manager_on_pfm_verified (&pfm_mgr->base);
	}

	return status;
}

static int pfm_manager_flash_clear_all_manifests (struct manifest_manager *manager)
{
	struct pfm_manager_flash *pfm_mgr = (struct pfm_manager_flash*) manager;
	int status;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_clear_all_manifests (&pfm_mgr->manifest_manager, false);
	if (status == 0) {
		pfm_manager_on_clear_active (&pfm_mgr->base);
	}

	return status;
}

/**
 * Initialize the manager for handling PFMs.
 *
 * @param manager The PFM manager to initialize.
 * @param pfm_region1 The PFM instance for the first flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pfm_region2 The PFM instance for the second flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state The state information for PFM management.
 * @param hash The hash engine to be used for PFM validation.
 * @param verification The module to be used for PFM verification.
 *
 * @return 0 if the PFM manager was successfully initialized or an error code.
 */
int pfm_manager_flash_init (struct pfm_manager_flash *manager, struct pfm_flash *pfm_region1,
	struct pfm_flash *pfm_region2, struct host_state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification)
{
	return pfm_manager_flash_init_port (manager, pfm_region1, pfm_region2, state, hash,
		verification, -1);
}

/**
 * Initialize the manager for handling PFMs.  The manager port identifier will be set as part of
 * initialization.
 *
 * @param manager The PFM manager to initialize.
 * @param pfm_region1 The PFM instance for the first flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pfm_region2 The PFM instance for the second flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state The state information for PFM management.
 * @param hash The hash engine to be used for PFM validation.
 * @param verification The module to be used for PFM verification.
 * @param port The port identifier to set.  A negative port ID will use the default value.
 *
 * @return 0 if the PFM manager was successfully initialized or an error code.
 */
int pfm_manager_flash_init_port (struct pfm_manager_flash *manager, struct pfm_flash *pfm_region1,
	struct pfm_flash *pfm_region2, struct host_state_manager *state, struct hash_engine *hash,
	struct signature_verification *verification, int port)
{
	int status;

	if ((manager == NULL) || (pfm_region1 == NULL) || (pfm_region2 == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct pfm_manager_flash));

	status = pfm_manager_init (&manager->base, hash, port);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init (&manager->manifest_manager, &manager->base.base,
		&pfm_region1->base.base, &pfm_region2->base.base, &pfm_region1->base_flash,
		&pfm_region2->base_flash, &state->base, hash, verification, 0, MANIFEST_LOGGING_EMPTY_PFM,
		false);
	if (status != 0) {
		goto manifest_base_error;
	}

	manager->base.get_active_pfm = pfm_manager_flash_get_active_pfm;
	manager->base.get_pending_pfm = pfm_manager_flash_get_pending_pfm;
	manager->base.free_pfm = pfm_manager_flash_free_pfm;

	manager->base.base.activate_pending_manifest = pfm_manager_flash_activate_pending_pfm;
	manager->base.base.clear_pending_region = pfm_manager_flash_clear_pending_region;
	manager->base.base.write_pending_data = pfm_manager_flash_write_pending_data;
	manager->base.base.verify_pending_manifest = pfm_manager_flash_verify_pending_pfm;
	manager->base.base.clear_all_manifests = pfm_manager_flash_clear_all_manifests;

	manager->host_state = state;

	return 0;

manifest_base_error:
	pfm_manager_release (&manager->base);
	return status;
}

/**
 * Release the resources used by a manager of PFMs in flash.
 *
 * @param manager The PFM manager to release.
 */
void pfm_manager_flash_release (struct pfm_manager_flash *manager)
{
	if (manager != NULL) {
		pfm_manager_release (&manager->base);
		manifest_manager_flash_release (&manager->manifest_manager);
	}
}
