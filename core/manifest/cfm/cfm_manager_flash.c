// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cfm_manager_flash.h"
#include "manifest/manifest_logging.h"
#include "system/system_state_manager.h"


/**
 * Get the CFM interface for a manifest on flash.
 *
 * @param manager The manager to query.
 * @param active Flag indicating if the interface for the active region should be returned.
 * Otherwise, the pending region will be returned.
 *
 * @return The requested CFM instance or null if there was an error.
 */
static const struct cfm* cfm_manager_flash_get_cfm (const struct cfm_manager_flash *manager,
	bool active)
{
	const struct cfm_flash *flash;
	const struct manifest_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	region = manifest_manager_flash_get_manifest_region (&manager->manifest_manager, active);
	if (region == NULL) {
		return NULL;
	}

	flash = (const struct cfm_flash*) region->manifest;

	return &flash->base;
}

const struct cfm* cfm_manager_flash_get_active_cfm (const struct cfm_manager *manager)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;

	return cfm_manager_flash_get_cfm (cfm_mgr, true);
}

const struct cfm* cfm_manager_flash_get_pending_cfm (const struct cfm_manager *manager)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;

	return cfm_manager_flash_get_cfm (cfm_mgr, false);
}

void cfm_manager_flash_free_cfm (const struct cfm_manager *manager, const struct cfm *cfm)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return;
	}

	manifest_manager_flash_free_manifest (&cfm_mgr->manifest_manager, (const struct manifest*) cfm);
}

int cfm_manager_flash_activate_pending_manifest (const struct manifest_manager *manager)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;
	int status;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = manifest_manager_flash_activate_pending_manifest (&cfm_mgr->manifest_manager);
	if (status == 0) {
		cfm_manager_on_cfm_activated (&cfm_mgr->base);
	}

	cfm_manager_on_cfm_activation_request (&cfm_mgr->base);

	return status;
}

int cfm_manager_flash_clear_pending_region (const struct manifest_manager *manager, size_t size)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_clear_pending_region (&cfm_mgr->manifest_manager, size);
}

int cfm_manager_flash_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;

	if (cfm_mgr == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_manager_flash_write_pending_data (&cfm_mgr->manifest_manager, data, length);
}

int cfm_manager_flash_verify_pending_manifest (const struct manifest_manager *manager)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;
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

int cfm_manager_flash_clear_all_manifests (const struct manifest_manager *manager)
{
	const struct cfm_manager_flash *cfm_mgr = (const struct cfm_manager_flash*) manager;
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
 * @param state Variable context for the CFM manager.  This must be uninitialized.
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
int cfm_manager_flash_init (struct cfm_manager_flash *manager,
	struct cfm_manager_flash_state *state, const struct cfm_flash *cfm_region1,
	const struct cfm_flash *cfm_region2, struct state_manager *state_mgr,
	const struct hash_engine *hash, const struct signature_verification *verification)
{
	int status;

	if ((manager == NULL) || (state == NULL) || (cfm_region1 == NULL) || (cfm_region2 == NULL) ||
		(state_mgr == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct cfm_manager_flash));

	status = cfm_manager_init (&manager->base, &state->base, hash);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init (&manager->manifest_manager, &state->flash_state,
		&manager->base.base, &cfm_region1->base.base, &cfm_region2->base.base,
		&cfm_region1->base_flash, &cfm_region2->base_flash, state_mgr, hash, verification,
		SYSTEM_STATE_MANIFEST_CFM, MANIFEST_LOGGING_EMPTY_CFM, false);
	if (status != 0) {
		cfm_manager_release (&manager->base);

		return status;
	}

	manager->base.get_active_cfm = cfm_manager_flash_get_active_cfm;
	manager->base.get_pending_cfm = cfm_manager_flash_get_pending_cfm;
	manager->base.free_cfm = cfm_manager_flash_free_cfm;

	manager->base.base.activate_pending_manifest = cfm_manager_flash_activate_pending_manifest;
	manager->base.base.clear_pending_region = cfm_manager_flash_clear_pending_region;
	manager->base.base.write_pending_data = cfm_manager_flash_write_pending_data;
	manager->base.base.verify_pending_manifest = cfm_manager_flash_verify_pending_manifest;
	manager->base.base.clear_all_manifests = cfm_manager_flash_clear_all_manifests;

	cfm_manager_flash_activate_pending_manifest (&manager->base.base);

	return 0;
}

/**
 * Initialize only the variable state for a manager of CFMs on flash.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int cfm_manager_flash_init_state (const struct cfm_manager_flash *manager)
{
	int status;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	status = cfm_manager_init_state (&manager->base);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_init_state (&manager->manifest_manager,
		MANIFEST_LOGGING_EMPTY_CFM);
	if (status != 0) {
		cfm_manager_release (&manager->base);

		return status;
	}

	cfm_manager_flash_activate_pending_manifest (&manager->base.base);

	return status;
}

/**
 * Release the resources used by a manager of CFMs in flash.
 *
 * @param manager The CFM manager to release.
 */
void cfm_manager_flash_release (const struct cfm_manager_flash *manager)
{
	if (manager != NULL) {
		cfm_manager_release (&manager->base);
		manifest_manager_flash_release (&manager->manifest_manager);
	}
}
