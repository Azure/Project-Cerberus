// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pfm_manager_flash.h"
#include "host_fw/host_state_manager.h"
#include "manifest/manifest_logging.h"


/**
 * Get the PFM interface for a manifest on flash.
 *
 * @param manager The manager to query.
 * @param active Flag indicating if the interface for the active region should be returned.
 * Otherwise, the pending region will be returned.
 *
 * @return The requested PFM instance or null if there was an error.
 */
static const struct pfm* pfm_manager_flash_get_pfm (const struct pfm_manager_flash *manager,
	bool active)
{
	const struct pfm_flash *flash;
	const struct manifest_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	region = manifest_manager_flash_get_manifest_region (&manager->manifest_manager, active);
	if (region == NULL) {
		return NULL;
	}

	flash = (const struct pfm_flash*) region->manifest;

	return &flash->base;
}

const struct pfm* pfm_manager_flash_get_active_pfm (const struct pfm_manager *manager)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;

	return pfm_manager_flash_get_pfm (pfm_mgr, true);
}

const struct pfm* pfm_manager_flash_get_pending_pfm (const struct pfm_manager *manager)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;

	return pfm_manager_flash_get_pfm (pfm_mgr, false);
}

void pfm_manager_flash_free_pfm (const struct pfm_manager *manager, const struct pfm *pfm)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return;
	}

	manifest_manager_flash_free_manifest (&pfm_mgr->manifest_manager, (const struct manifest*) pfm);
}

int pfm_manager_flash_activate_pending_manifest (const struct manifest_manager *manager)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;
	int status;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_activate_pending_manifest (&pfm_mgr->manifest_manager);
	if (status == 0) {
		host_state_manager_set_pfm_dirty (pfm_mgr->host_state, false);
		pfm_manager_on_pfm_activated (&pfm_mgr->base);
	}

	pfm_manager_on_pfm_activation_request (&pfm_mgr->base);

	return status;
}

int pfm_manager_flash_clear_pending_region (const struct manifest_manager *manager, size_t size)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_clear_pending_region (&pfm_mgr->manifest_manager, size);
}

int pfm_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;

	if (pfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_write_pending_data (&pfm_mgr->manifest_manager, data, length);
}

int pfm_manager_flash_verify_pending_manifest (const struct manifest_manager *manager)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;
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

int pfm_manager_flash_clear_all_manifests (const struct manifest_manager *manager)
{
	const struct pfm_manager_flash *pfm_mgr = (const struct pfm_manager_flash*) manager;
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
 * @param state Variable context for the PFM manager.  This must be uninitialized.
 * @param pfm_region1 The PFM instance for the first flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pfm_region2 The PFM instance for the second flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state_mgr The state information for PFM management.
 * @param hash The hash engine to be used for PFM validation.
 * @param verification The module to be used for PFM verification.
 *
 * @return 0 if the PFM manager was successfully initialized or an error code.
 */
int pfm_manager_flash_init (struct pfm_manager_flash *manager,
	struct pfm_manager_flash_state *state, const struct pfm_flash *pfm_region1,
	const struct pfm_flash *pfm_region2, struct host_state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification)
{
	return pfm_manager_flash_init_port (manager, state, pfm_region1, pfm_region2, state_mgr, hash,
		verification, -1);
}

/**
 * Initialize the manager for handling PFMs.  The manager port identifier will be set as part of
 * initialization.
 *
 * @param manager The PFM manager to initialize.
 * @param state Variable context for the PFM manager.  This must be uninitialized.
 * @param pfm_region1 The PFM instance for the first flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash
 * erase block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pfm_region2 The PFM instance for the second flash region that can hold a PFM.
 * This region does not need to have a valid PFM. The region is expected to a single flash erase
 * block as defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state_mgr The state information for PFM management.
 * @param hash The hash engine to be used for PFM validation.
 * @param verification The module to be used for PFM verification.
 * @param port The port identifier to set.  A negative port ID will use the default value.
 *
 * @return 0 if the PFM manager was successfully initialized or an error code.
 */
int pfm_manager_flash_init_port (struct pfm_manager_flash *manager,
	struct pfm_manager_flash_state *state, const struct pfm_flash *pfm_region1,
	const struct pfm_flash *pfm_region2, struct host_state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification, int port)
{
	int status;

	if ((manager == NULL) || (state == NULL) || (pfm_region1 == NULL) || (pfm_region2 == NULL) ||
		(state_mgr == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct pfm_manager_flash));

	status = pfm_manager_init (&manager->base, &state->base, hash, port);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init (&manager->manifest_manager, &state->flash_state,
		&manager->base.base, &pfm_region1->base.base, &pfm_region2->base.base,
		&pfm_region1->base_flash, &pfm_region2->base_flash, &state_mgr->base, hash, verification, 0,
		MANIFEST_LOGGING_EMPTY_PFM, false);
	if (status != 0) {
		goto manifest_base_error;
	}

	manager->base.get_active_pfm = pfm_manager_flash_get_active_pfm;
	manager->base.get_pending_pfm = pfm_manager_flash_get_pending_pfm;
	manager->base.free_pfm = pfm_manager_flash_free_pfm;

	manager->base.base.activate_pending_manifest = pfm_manager_flash_activate_pending_manifest;
	manager->base.base.clear_pending_region = pfm_manager_flash_clear_pending_region;
	manager->base.base.write_pending_data = pfm_manager_flash_write_pending_data;
	manager->base.base.verify_pending_manifest = pfm_manager_flash_verify_pending_manifest;
	manager->base.base.clear_all_manifests = pfm_manager_flash_clear_all_manifests;

	manager->host_state = state_mgr;

	return 0;

manifest_base_error:
	pfm_manager_release (&manager->base);

	return status;
}

/**
 * Initialize only the variable state for a manager of PFMs on flash.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int pfm_manager_flash_init_state (const struct pfm_manager_flash *manager)
{
	int status;

	if ((manager == NULL) || (manager->host_state == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = pfm_manager_init_state (&manager->base);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init_state (&manager->manifest_manager,
		MANIFEST_LOGGING_EMPTY_PFM);
	if (status != 0) {
		pfm_manager_release (&manager->base);
	}

	return status;
}

/**
 * Release the resources used by a manager of PFMs in flash.
 *
 * @param manager The PFM manager to release.
 */
void pfm_manager_flash_release (const struct pfm_manager_flash *manager)
{
	if (manager != NULL) {
		pfm_manager_release (&manager->base);
		manifest_manager_flash_release (&manager->manifest_manager);
	}
}
