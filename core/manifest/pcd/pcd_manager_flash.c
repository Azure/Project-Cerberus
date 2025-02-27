// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pcd_manager_flash.h"
#include "manifest/manifest_logging.h"
#include "system/system_state_manager.h"


/**
 * Get the PCD interface for a manifest on flash.
 *
 * @param manager The manager to query.
 * @param active Flag indicating if the interface for the active region should be returned.
 * Otherwise, the pending region will be returned.
 *
 * @return The requested PCD instance or null if there was an error.
 */
static const struct pcd* pcd_manager_flash_get_pcd (const struct pcd_manager_flash *manager,
	bool active)
{
	const struct pcd_flash *flash;
	const struct manifest_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	region = manifest_manager_flash_get_manifest_region (&manager->manifest_manager, active);
	if (region == NULL) {
		return NULL;
	}

	flash = (const struct pcd_flash*) region->manifest;

	return &flash->base;
}

const struct pcd* pcd_manager_flash_get_active_pcd (const struct pcd_manager *manager)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;

	return pcd_manager_flash_get_pcd (pcd_mgr, true);
}

void pcd_manager_flash_free_pcd (const struct pcd_manager *manager, const struct pcd *pcd)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;

	if (pcd_mgr == NULL) {
		return;
	}

	manifest_manager_flash_free_manifest (&pcd_mgr->manifest_manager, (const struct manifest*) pcd);
}

int pcd_manager_flash_activate_pending_manifest (const struct manifest_manager *manager)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;
	int status;

	if (pcd_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_activate_pending_manifest (&pcd_mgr->manifest_manager);
	if (status == 0) {
		pcd_manager_on_pcd_activated (&pcd_mgr->base);
	}

	pcd_manager_on_pcd_activation_request (&pcd_mgr->base);

	return status;
}

int pcd_manager_flash_clear_pending_region (const struct manifest_manager *manager, size_t size)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;

	if (pcd_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_clear_pending_region (&pcd_mgr->manifest_manager, size);
}

int pcd_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;

	if (pcd_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_write_pending_data (&pcd_mgr->manifest_manager, data, length);
}

int pcd_manager_flash_verify_pending_manifest (const struct manifest_manager *manager)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;
	int status;

	if (pcd_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_verify_pending_manifest (&pcd_mgr->manifest_manager);
	if (status == 0) {
		pcd_manager_on_pcd_verified (&pcd_mgr->base, pcd_manager_flash_get_pcd (pcd_mgr, false));
	}

	return status;
}

int pcd_manager_flash_clear_all_manifests (const struct manifest_manager *manager)
{
	const struct pcd_manager_flash *pcd_mgr = (const struct pcd_manager_flash*) manager;
	int status;

	if (pcd_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_clear_all_manifests (&pcd_mgr->manifest_manager, false);
	if (status == 0) {
		pcd_manager_on_clear_active (&pcd_mgr->base);
	}

	return status;
}

/**
 * Initialize the manager for handling PCDs.
 *
 * @param manager The PCD manager to initialize.
 * @param state Variable context for the PCD manager.  This must be uninitialized.
 * @param pcd_region1 The PCD instance for the first flash region that can hold a PCD. This region
 * does not need to have a valid PCD.The region is expected to a single flash erase  block as
 * defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param pcd_region2 The PCD instance for the second flash region that can hold a PCD. This region
 * does not need to have a valid PCD. The region is expected to a single flash erase block as
 * defined by FLASH_BLOCK_SIZE, aligned to the beginning of the block.
 * @param state The state information for PCD management.
 * @param hash The hash engine to be used for PCD validation.
 * @param verification The module to be used for PCD verification.
 *
 * @return 0 if the PCD manager was successfully initialized or an error code.
 */
int pcd_manager_flash_init (struct pcd_manager_flash *manager,
	struct pcd_manager_flash_state *state, const struct pcd_flash *pcd_region1,
	const struct pcd_flash *pcd_region2, struct state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification)
{
	int status;

	if ((manager == NULL) || (state == NULL) || (pcd_region1 == NULL) || (pcd_region2 == NULL) ||
		(state_mgr == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct pcd_manager_flash));

	status = pcd_manager_init (&manager->base, &state->base, hash);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init (&manager->manifest_manager, &state->flash_state,
		&manager->base.base, &pcd_region1->base.base, &pcd_region2->base.base,
		&pcd_region1->base_flash, &pcd_region2->base_flash, state_mgr, hash, verification,
		SYSTEM_STATE_MANIFEST_PCD, MANIFEST_LOGGING_EMPTY_PCD, true);
	if (status != 0) {
		pcd_manager_release (&manager->base);

		return status;
	}

	manager->base.get_active_pcd = pcd_manager_flash_get_active_pcd;
	manager->base.free_pcd = pcd_manager_flash_free_pcd;

	manager->base.base.activate_pending_manifest = pcd_manager_flash_activate_pending_manifest;
	manager->base.base.clear_pending_region = pcd_manager_flash_clear_pending_region;
	manager->base.base.write_pending_data = pcd_manager_flash_write_pending_data;
	manager->base.base.verify_pending_manifest = pcd_manager_flash_verify_pending_manifest;
	manager->base.base.clear_all_manifests = pcd_manager_flash_clear_all_manifests;

	pcd_manager_flash_activate_pending_manifest (&manager->base.base);

	return 0;
}

/**
 * Initialize only the variable state for a manager of PCDs on flash.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int pcd_manager_flash_init_state (const struct pcd_manager_flash *manager)
{
	int status;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = pcd_manager_init_state (&manager->base);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init_state (&manager->manifest_manager,
		MANIFEST_LOGGING_EMPTY_PCD);
	if (status != 0) {
		pcd_manager_release (&manager->base);

		return status;
	}

	pcd_manager_flash_activate_pending_manifest (&manager->base.base);

	return 0;
}

/**
 * Release the resources used by a manager of PCDs in flash.
 *
 * @param manager The PCD manager to release.
 */
void pcd_manager_flash_release (const struct pcd_manager_flash *manager)
{
	if (manager != NULL) {
		pcd_manager_release (&manager->base);
		manifest_manager_flash_release (&manager->manifest_manager);
	}
}
