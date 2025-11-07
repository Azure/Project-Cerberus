// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "manifest_logging.h"
#include "manifest_manager.h"
#include "manifest_manager_flash.h"
#include "crypto/ecc.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/**
 * Check if a single manifest flash region contains a valid manifest.
 *
 * @param manager The manifest manager to use for verification.
 * @param manifest The manifest interface to use for verification.
 * @param region The region to verify.
 *
 * @return 0 if the manifest was determined to be either valid or invalid. An error code if the
 * validity of the manifest could not be determined.
 */
static int manifest_manager_flash_verify_manifest (const struct manifest_manager_flash *manager,
	const struct manifest *manifest, const struct manifest_manager_flash_region *region)
{
	int status = manifest->verify (manifest, manager->hash, manager->verification, NULL, 0);

	if (status == 0) {
		region->state->is_valid = true;
	}
	else if ((status == SIG_VERIFICATION_BAD_SIGNATURE) ||
		(ROT_GET_MODULE (status) == ROT_MODULE_MANIFEST) ||
		(ROT_GET_MODULE (status) == ROT_MODULE_PFM) ||
		(ROT_GET_MODULE (status) == ROT_MODULE_CFM) ||
		(ROT_GET_MODULE (status) == ROT_MODULE_PCD)) {
		/* Don't fail for any errors in the manifest data.  Just mark the region as invalid. */
		region->state->is_valid = false;
		status = 0;
	}

	return status;
}

/**
 * If there is both an active and pending manifest available, check the ID of the pending manifest
 * to see that it is valid relative to the active manifest. If not, mark the pending manifest as
 * invalid.
 *
 * @param manager The manifest manager to use for validation.
 *
 * @return 0 if the check completed successfully or an error code.
 */
static int manifest_manager_flash_check_pending_manifest_id (
	const struct manifest_manager_flash *manager)
{
	const struct manifest_manager_flash_region *active;
	const struct manifest_manager_flash_region *pending;
	int status = 0;

	active = manifest_manager_flash_get_region (manager, true);
	pending = manifest_manager_flash_get_region (manager, false);

	if (active->state->is_valid && pending->state->is_valid) {
		status = manifest_flash_compare_id (active->flash, pending->flash);
		if (status != 0) {
			pending->state->is_valid = false;
			status = MANIFEST_MANAGER_INVALID_ID;
		}
	}

	return status;
}

/**
 * If there is both an active and pending manifest, check that the platform identifier of the
 * pending manifest matches the active.  If not, mark the pending manifest as invalid.
 *
 * @param manager The manifest manager to use for validation.
 *
 * @return 0 if the check completed successfully or an error code.
 */
static int manifest_manager_flash_check_pending_platform_id (
	const struct manifest_manager_flash *manager)
{
	const struct manifest_manager_flash_region *active;
	const struct manifest_manager_flash_region *pending;
	int status = 0;

	active = manifest_manager_flash_get_region (manager, true);
	pending = manifest_manager_flash_get_region (manager, false);

	if (active->state->is_valid && pending->state->is_valid) {
		status = manifest_flash_compare_platform_id (active->flash, pending->flash,
			manager->sku_upgrade_permitted);
		if (status == 1) {
			pending->state->is_valid = false;
			status = MANIFEST_MANAGER_INCOMPATIBLE;
		}
		else if (status != 0) {
			pending->state->is_valid = false;
		}
	}

	return status;
}

/**
 * If the pending manifest is empty, clear the manifests.
 *
 * @param manager The manifest manager to update.
 * @param clear_msg The logging message identifier to use when manifests are cleared.
 *
 * @return 0 if the check completed successfully or an error code.
 */
static int manifest_manager_flash_check_empty_manifest (
	const struct manifest_manager_flash *manager, int clear_msg)
{
	const struct manifest_manager_flash_region *pending;
	int status = 0;

	pending = manifest_manager_flash_get_region (manager, false);
	if (pending->state->is_valid) {
		status = pending->manifest->is_empty (pending->manifest);
		if (status == 1) {
			status = manifest_manager_flash_clear_all_manifests (manager, true);

			debug_log_create_entry ((status ==
				0) ? DEBUG_LOG_SEVERITY_WARNING : DEBUG_LOG_SEVERITY_ERROR,
				DEBUG_LOG_COMPONENT_MANIFEST, clear_msg, manifest_manager_get_port (manager->base),
				status);
		}
	}

	return status;
}

/**
 * Initialize a manager for handling manifests on flash.
 *
 * @param manager The manifest manager to initialize.
 * @param state Variable context for managing the manifests on flash.  This must be uninitialized.
 * @param base The base manager associated with this manager instance.
 * @param region1 The manifest instance for the first flash region that can hold a manifest.
 * @param region2 The manifest instance for the second flash region that can hold a manifest.
 * @param region1_flash Flash access for the region 1 manifest.
 * @param region2_flash Flash access for the region 2 manifest.
 * @param state_mgr The state information for manifest management.
 * @param hash The hash engine to be used for manifest validation.
 * @param verification The module to use for manifest verification.
 * @param manifest_index State manager manifest index to use for maintaining active region state.
 * @param log_msg_empty The log message identifier to use when an empty pending manifest is present.
 * @param sku_upgrade_permitted Manifest permitted to upgrade from generic to SKU-specific.
 *
 * @return 0 if the manifest manager was successfully initialized or an error code.
 */
int manifest_manager_flash_init (struct manifest_manager_flash *manager,
	struct manifest_manager_flash_state *state, const struct manifest_manager *base,
	const struct manifest *region1, const struct manifest *region2,
	const struct manifest_flash *region1_flash, const struct manifest_flash *region2_flash,
	const struct state_manager *state_mgr, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t manifest_index,
	uint8_t log_msg_empty, bool sku_upgrade_permitted)
{
	manager->state = state;
	manager->base = base;
	manager->region1.manifest = region1;
	manager->region1.flash = region1_flash;
	manager->region1.state = &state->region1;
	manager->region2.manifest = region2;
	manager->region2.flash = region2_flash;
	manager->region2.state = &state->region2;
	manager->state_mgr = state_mgr;
	manager->hash = hash;
	manager->verification = verification;
	manager->manifest_index = manifest_index;
	manager->sku_upgrade_permitted = sku_upgrade_permitted;

	return manifest_manager_flash_init_state (manager, log_msg_empty);
}

/**
 * Initialize only the variable state for a manager handling manifests on flash.  The rest of the
 * manager is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The manager that contains the state to initialize.
 * @param log_msg_empty The log message identifier to use when an empty pending manifest is present.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_manager_flash_init_state (const struct manifest_manager_flash *manager,
	uint8_t log_msg_empty)
{
	int status;

	if ((manager->state == NULL) || (manager->region1.manifest == NULL) ||
		(manager->region2.manifest == NULL) || (manager->state_mgr == NULL) ||
		(manager->hash == NULL) || (manager->verification == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager->state, 0, sizeof (*manager->state));

	status = manager->state_mgr->is_manifest_valid (manager->state_mgr, manager->manifest_index);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_verify_manifest (manager, manager->region1.manifest,
		&manager->region1);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_verify_manifest (manager, manager->region2.manifest,
		&manager->region2);
	if (status != 0) {
		return status;
	}

	status = manifest_manager_flash_check_pending_manifest_id (manager);
	if ((status != 0) && (status != MANIFEST_MANAGER_INVALID_ID)) {
		return status;
	}

	status = manifest_manager_flash_check_pending_platform_id (manager);
	if ((status != 0) && (status != MANIFEST_MANAGER_INCOMPATIBLE)) {
		return status;
	}

	status = flash_updater_init (&manager->region1.state->updater,
		manifest_flash_get_flash (manager->region1.flash),
		manifest_flash_get_addr (manager->region1.flash), FLASH_BLOCK_SIZE);
	if (status != 0) {
		return status;
	}

	status = flash_updater_init (&manager->region2.state->updater,
		manifest_flash_get_flash (manager->region2.flash),
		manifest_flash_get_addr (manager->region2.flash), FLASH_BLOCK_SIZE);
	if (status != 0) {
		goto exit_region1;
	}

	status = manifest_manager_flash_check_empty_manifest (manager, log_msg_empty);
	if (status != 0) {
		goto exit_region2;
	}

	status = platform_mutex_init (&manager->state->lock);
	if (status != 0) {
		goto exit_region2;
	}

	return 0;

exit_region2:
	flash_updater_release (&manager->region2.state->updater);
exit_region1:
	flash_updater_release (&manager->region1.state->updater);

	return status;
}

/**
 * Release the resources used by a manager of manifests in flash.
 *
 * @param manager The manifest manager to release.
 */
void manifest_manager_flash_release (const struct manifest_manager_flash *manager)
{
	platform_mutex_free (&manager->state->lock);
	flash_updater_release (&manager->region1.state->updater);
	flash_updater_release (&manager->region2.state->updater);
}

/**
 * Get the active or pending manifest region based on the current system state.
 *
 * @param manager The manifest manager instance to query.
 * @param active Flag to indicate which region to retrieve, active or pending.
 *
 * @return The manifest region.
 */
const struct manifest_manager_flash_region* manifest_manager_flash_get_region (
	const struct manifest_manager_flash *manager, bool active)
{
	enum manifest_region current = manager->state_mgr->get_active_manifest (manager->state_mgr,
		manager->manifest_index);

	if (current == MANIFEST_REGION_1) {
		return (active) ? &manager->region1 : &manager->region2;
	}
	else {
		return (active) ? &manager->region2 : &manager->region1;
	}
}

/**
 * Get the active manifest region for the protected flash. The manifest instance must be released
 * with the manager.
 *
 * @param manager The manifest manager to query.
 * @param active Flag to indicate which region to retrieve, active or pending.
 *
 * @return The active manifest region or null if there is no active manifest.
 */
const struct manifest_manager_flash_region* manifest_manager_flash_get_manifest_region (
	const struct manifest_manager_flash *manager, bool active)
{
	const struct manifest_manager_flash_region *region;

	platform_mutex_lock (&manager->state->lock);

	region = manifest_manager_flash_get_region (manager, active);
	if (region->state->is_valid) {
		region->state->ref_count++;
	}

	platform_mutex_unlock (&manager->state->lock);

	return (region->state->is_valid) ? region : NULL;
}

/**
 * Release a manifest instance retrieved from the manager. Manifest instances must only be
 * released by the manager that allocated them.
 *
 * @param manager The manifest manager that allocated the manifest instance.
 * @param manifest The manifest to release.
 */
void manifest_manager_flash_free_manifest (const struct manifest_manager_flash *manager,
	const struct manifest *manifest)
{
	const struct manifest_manager_flash_region *region;

	platform_mutex_lock (&manager->state->lock);

	if (manifest == manager->region1.manifest) {
		region = &manager->region1;
	}
	else if (manifest == manager->region2.manifest) {
		region = &manager->region2;
	}
	else {
		region = NULL;
	}

	if (region && (region->state->ref_count > 0)) {
		region->state->ref_count--;
	}

	platform_mutex_unlock (&manager->state->lock);
}

/**
 * Activate the pending manifest and discard the active manifest.
 *
 * @param manager The manifest manager to update.
 *
 * @return 0 if the pending manifest was successfully activated or an error if there no pending
 * manifest to activate.
 */
int manifest_manager_flash_activate_pending_manifest (const struct manifest_manager_flash *manager)
{
	enum manifest_region active;
	int status = 0;

	platform_mutex_lock (&manager->state->lock);

	active = manager->state_mgr->get_active_manifest (manager->state_mgr, manager->manifest_index);

	if (active == MANIFEST_REGION_1) {
		if (!manager->region2.state->is_valid) {
			status = MANIFEST_MANAGER_NONE_PENDING;
			goto exit;
		}

		manager->state_mgr->save_active_manifest (manager->state_mgr, manager->manifest_index,
			MANIFEST_REGION_2);
		manager->region1.state->is_valid = false;
	}
	else {
		if (!manager->region1.state->is_valid) {
			status = MANIFEST_MANAGER_NONE_PENDING;
			goto exit;
		}

		manager->state_mgr->save_active_manifest (manager->state_mgr, manager->manifest_index,
			MANIFEST_REGION_1);
		manager->region2.state->is_valid = false;
	}

exit:
	platform_mutex_unlock (&manager->state->lock);

	return status;
}

/**
 * Clear the pending manifest region in order to accept new manifest data.
 *
 * @param manager The manifest manager for the pending region to clear.
 * @param size Size of incoming manifest
 *
 * @return 0 if the pending manifest region was successfully cleared or an error code.
 */
int manifest_manager_flash_clear_pending_region (const struct manifest_manager_flash *manager,
	size_t size)
{
	const struct manifest_manager_flash_region *region;
	int status;

	platform_mutex_lock (&manager->state->lock);

	region = manifest_manager_flash_get_region (manager, false);
	if (region->state->ref_count == 0) {
		status = flash_updater_check_update_size (&region->state->updater, size);
		if (status != 0) {
			platform_mutex_unlock (&manager->state->lock);

			return status;
		}

		manager->state->updating = &region->state->updater;
		region->state->is_valid = false;
	}
	else {
		platform_mutex_unlock (&manager->state->lock);

		return MANIFEST_MANAGER_PENDING_IN_USE;
	}

	platform_mutex_unlock (&manager->state->lock);

	return flash_updater_prepare_for_update_erase_all (manager->state->updating, size);
}

/**
 * Write data to the pending manifest region. This data must be written sequentially.
 *
 * @param manager The manifest interface to use.
 * @param data The data that should be written.
 * @param length The length of the data to write.
 *
 * @return 0 if the data was successfully written or an error code.
 */
int manifest_manager_flash_write_pending_data (const struct manifest_manager_flash *manager,
	const uint8_t *data, size_t length)
{
	if (data == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (manager->state->updating == NULL) {
		return MANIFEST_MANAGER_NOT_CLEARED;
	}

	return flash_updater_write_update_data (manager->state->updating, data, length);
}

/**
 * After all manifest has been written to the pending area, verify that the region contains a
 * valid manifest.
 *
 * @param manager The manifest manager to use for validation.
 *
 * @return 0 if the pending manifest was successfully validated or an error code.
 */
int manifest_manager_flash_verify_pending_manifest (const struct manifest_manager_flash *manager)
{
	const struct manifest_manager_flash_region *region;
	int status = 0;

	platform_mutex_lock (&manager->state->lock);

	if (flash_updater_get_remaining_bytes (manager->state->updating) > 0) {
		status = MANIFEST_MANAGER_INCOMPLETE_UPDATE;
		goto exit;
	}

	region = manifest_manager_flash_get_region (manager, false);
	if (!region->state->is_valid) {
		if (manager->state->updating != NULL) {
			status = region->manifest->verify (region->manifest, manager->hash,
				manager->verification, NULL, 0);
			if (status == 0) {
				region->state->is_valid = true;
			}
		}
		else {
			status = MANIFEST_MANAGER_NONE_PENDING;
		}
	}
	else {
		status = MANIFEST_MANAGER_HAS_PENDING;
	}

	if (status == 0) {
		status = manifest_manager_flash_check_pending_manifest_id (manager);
		if (status != 0) {
			goto exit;
		}

		status = manifest_manager_flash_check_pending_platform_id (manager);
		if (status != 0) {
			goto exit;
		}

		if (manager->post_verify) {
			status = manager->post_verify (manager);
			if (status != 0) {
				goto exit;
			}
		}
	}

exit:
	manager->state->updating = NULL;

	platform_mutex_unlock (&manager->state->lock);

	return status;
}

/**
 * Erase a single manifest and mark it as invalid.
 *
 * @param region The manifest region to erase.
 * @param in_use_error The error to return if the region is in use.
 *
 * @return 0 if the region was erased or an error code.
 */
static int manifest_manager_flash_clear_manifest (
	const struct manifest_manager_flash_region *region, int in_use_error)
{
	if (region->state->ref_count != 0) {
		return in_use_error;
	}

	region->state->is_valid = false;

	return flash_erase_region (region->state->updater.flash, region->state->updater.base_addr,
		FLASH_BLOCK_SIZE);
}

/**
 * Erase both the active and pending regions and mark both manifests as invalid.
 *
 * @param manager The manifest manager to clear.
 * @param no_lock Flag to skip taking the synchronization lock.
 *
 * @return 0 if the manifests were erased or an error code.
 */
int manifest_manager_flash_clear_all_manifests (const struct manifest_manager_flash *manager,
	bool no_lock)
{
	int status;

	if (!no_lock) {
		platform_mutex_lock (&manager->state->lock);
	}

	status = manifest_manager_flash_clear_manifest (manifest_manager_flash_get_region (manager,
		false), MANIFEST_MANAGER_PENDING_IN_USE);
	if (status != 0) {
		goto exit;
	}

	manager->state->updating = NULL;
	status = manifest_manager_flash_clear_manifest (manifest_manager_flash_get_region (manager,
		true), MANIFEST_MANAGER_ACTIVE_IN_USE);

exit:
	if (!no_lock) {
		platform_mutex_unlock (&manager->state->lock);
	}

	return status;
}
