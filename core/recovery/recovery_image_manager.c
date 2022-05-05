// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "common/common_math.h"
#include "crypto/ecc.h"
#include "flash/flash_util.h"
#include "host_fw/host_processor_dual.h"
#include "recovery_image_manager.h"
#include "recovery_image_header.h"
#include "recovery_image_section_header.h"
#include "recovery_logging.h"


/**
 * Get the requested recovery image region.
 *
 * @param manager The recovery image manager instance to query.
 * @param active Flag to indicate to retrieve the active or inactive region.
 *
 * @return The recovery image region.
 */
static struct recovery_image_manager_flash_region* recovery_image_manager_get_region (
	struct recovery_image_manager *manager, bool active)
{
	return &manager->region1;
}

/**
 * Get the requested recovery image region based on the host state.
 *
 * @param manager The recovery image manager instance to query.
 * @param active Flag to indicate to retrieve the active or inactive region.
 *
 * @return The recovery image region.
 */
static struct recovery_image_manager_flash_region* recovery_image_manager_get_region_two_region (
	struct recovery_image_manager *manager, bool active)
{
	enum recovery_image_region current;

	current = host_state_manager_get_active_recovery_image (manager->state);
	if (current == RECOVERY_IMAGE_REGION_1) {
		return (active) ? &manager->region1 : &manager->region2;
	}
	else {
		return (active) ? &manager->region2 : &manager->region1;
	}
}

/**
 * Notify all observers of an event for a recovery image.  The recovery image will be released to
 * the manager upon completion.
 *
 * @param manager The manager generating the event.
 * @param image The recovery image the event is for.
 * @param callback_offset The offset in the observer structure for the notification to call.
 */
static void recovery_image_manager_notify_observers (struct recovery_image_manager *manager,
	struct recovery_image *image, size_t callback_offset)
{
	observable_notify_observers_with_ptr (&manager->observable, callback_offset, image);

	if (image) {
		manager->free_recovery_image (manager, image);
	}
}

/**
 * Check if a recovery image flash region contains a valid recovery image.
 *
 * @param manager The recovery image manager to use for verification.
 * @param manifest The recovery image interface to use for verification.
 * @param region The region to verify.
 * @param pfm The PFM manager to use for verification.
 *
 * @return 0 if the recovery image was determined to be either valid or invalid. An error code if
 * the validity of the recovery image could not be determined.
 */
static int recovery_image_manager_verify_recovery_image (struct recovery_image_manager *manager,
	struct recovery_image *image, struct recovery_image_manager_flash_region *region,
	struct pfm_manager *pfm)
{
	int status = image->verify (image, manager->hash, manager->verification, NULL, 0, pfm);

	if (status == 0) {
		region->is_valid = true;
	}
	else if ((status == RSA_ENGINE_BAD_SIGNATURE) || (status == ECC_ENGINE_BAD_SIGNATURE) ||
		(status == RECOVERY_IMAGE_MALFORMED) || (status == RECOVERY_IMAGE_INCOMPATIBLE) ||
		(status == IMAGE_HEADER_NOT_MINIMUM_SIZE) || (status == IMAGE_HEADER_BAD_MARKER) ||
		(status == IMAGE_HEADER_TOO_LONG) || (status == RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH) ||
		(status == RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID) ||
		(status == RECOVERY_IMAGE_HEADER_BAD_VERSION_ID) ||
		(status == RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH) ||
		(status == RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH) ||
		(status == RECOVERY_IMAGE_INVALID_SECTION_ADDRESS)) {
		region->is_valid = false;
		status = 0;
	}

	return status;
}

/**
 * Add an observer to be notified of recovery image management events.  An observer can only be
 * added to the list once.  The order in which observers are notified is not guaranteed to be the
 * same as the order in which they were added.
 *
 * @param manager The manager to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was added for notifications or an error code.
 */
int recovery_image_manager_add_observer (struct recovery_image_manager *manager,
	struct recovery_image_observer *observer)
{
	if (manager == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->observable, observer);
}

/**
 * Remove an observer so it will no longer be notified of recovery image management events.
 *
 * @param manager The manager to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int recovery_image_manager_remove_observer (struct recovery_image_manager *manager,
	struct recovery_image_observer *observer)
{
	if (manager == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->observable, observer);
}

/**
 * Update a flash region to be the active region. Invalidate the other flash region if it is
 * enabled.
 *
 * @param manager The manager to update.
 * @param region The flash region to update to active.
 */
static void recovery_image_manager_update_active_region (struct recovery_image_manager *manager,
	struct recovery_image_manager_flash_region *region)
{
	struct recovery_image_manager_flash_region *active_region;
	enum recovery_image_region active;

	region->is_valid = true;
	active_region = manager->internal.get_region (manager, true);
	if (region != active_region) {
		active = host_state_manager_get_active_recovery_image (manager->state);
		if (active == RECOVERY_IMAGE_REGION_1) {
			host_state_manager_save_active_recovery_image (manager->state, RECOVERY_IMAGE_REGION_2);
			manager->region1.is_valid = false;
		}
		else {
			host_state_manager_save_active_recovery_image (manager->state, RECOVERY_IMAGE_REGION_1);
			manager->region2.is_valid = false;
		}
	}
}

static struct recovery_image* recovery_image_manager_get_active_recovery_image (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_flash_region *region;

	if (manager == NULL) {
		return NULL;
	}

	platform_mutex_lock (&manager->lock);

	region = manager->internal.get_region (manager, true);
	if (region->is_valid) {
		region->ref_count++;
	}

	platform_mutex_unlock (&manager->lock);

	return (region->is_valid) ? region->image : NULL;
}

static int recovery_image_manager_clear_recovery_image_region (
	struct recovery_image_manager *manager, size_t size)
{
	struct recovery_image_manager_flash_region *region;
	bool prev_valid = false;
	int status;

	if (manager == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	region = manager->internal.get_region (manager, false);
	if (region->ref_count == 0) {
		status = flash_updater_check_update_size (&region->updater, size);
		if (status != 0) {
			platform_mutex_unlock (&manager->lock);
			return status;
		}

		manager->updating = &region->updater;
		if (region->is_valid) {
			prev_valid = true;
		}
		region->is_valid = false;
	}
	else {
		platform_mutex_unlock (&manager->lock);
		return RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE;
	}

	platform_mutex_unlock (&manager->lock);

	status = flash_updater_prepare_for_update (manager->updating, size);
	if ((manager->region2.image == NULL) && prev_valid) {
		observable_notify_observers (&manager->observable,
			offsetof (struct recovery_image_observer, on_recovery_image_deactivated));
	}

	return status;
}

static void recovery_image_manager_free_recovery_image (struct recovery_image_manager *manager,
	struct recovery_image *image)
{
	struct recovery_image_manager_flash_region *region;

	if (manager == NULL) {
		return;
	}

	platform_mutex_lock (&manager->lock);

	if (image == manager->region1.image) {
		region = &manager->region1;
	}
	else if (image == manager->region2.image) {
		region = &manager->region2;
	}
	else {
		region = NULL;
	}

	if (region && (region->ref_count > 0)) {
		region->ref_count--;
	}

	platform_mutex_unlock (&manager->lock);
}

static int recovery_image_manager_write_recovery_image_data (struct recovery_image_manager *manager,
	const uint8_t *data, size_t length)
{
	if ((manager == NULL) || (data == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	if (manager->updating == NULL) {
		return RECOVERY_IMAGE_MANAGER_NOT_CLEARED;
	}

	return flash_updater_write_update_data (manager->updating, data, length);
}

static int recovery_image_manager_activate_recovery_image (struct recovery_image_manager *manager)
{
	struct recovery_image_manager_flash_region *region;
	int status = 0;
	bool is_valid;

	if (manager == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	if (flash_updater_get_remaining_bytes (manager->updating) > 0) {
		platform_mutex_unlock (&manager->lock);
		return RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE;
	}

	region = manager->internal.get_region (manager, false);
	is_valid = region->is_valid;
	if (!region->is_valid) {
		if (manager->updating != NULL) {
			status = region->image->verify (region->image, manager->hash,
				manager->verification, NULL, 0, manager->pfm);
			if (status == 0) {
				recovery_image_manager_update_active_region (manager, region);
			}
			else {
				goto exit;
			}
		}
		else  {
			status = RECOVERY_IMAGE_MANAGER_NONE_PENDING;
			goto exit;
		}
	}

exit:
	manager->updating = NULL;
	platform_mutex_unlock (&manager->lock);

	if (region->is_valid && (is_valid != region->is_valid)) {
		recovery_image_manager_notify_observers (manager,
			manager->get_active_recovery_image (manager),
			offsetof (struct recovery_image_observer, on_recovery_image_activated));
	}

	return status;
}

static struct flash_updater* recovery_image_manager_get_flash_update_manager (
	struct recovery_image_manager *manager)
{
	if (manager == NULL) {
		return NULL;
	}

	return manager->updating;
}

/**
 * Erase a single recovery image region and mark it as invalid.
 *
 * @param region The recovery image region to erase.
 *
 * @return 0 if the region was erased or an error code.
 */
static int recovery_image_manager_erase_recovery_region (
	struct recovery_image_manager_flash_region *region)
{
	if (region->ref_count != 0) {
		return RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE;
	}

	region->is_valid = false;
	return flash_erase_region (region->updater.flash, region->updater.base_addr,
		region->updater.max_size);
}

static int recovery_image_manager_erase_all_recovery_regions (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_flash_region *region1;
	struct recovery_image_manager_flash_region *region2;
	bool prev_valid = false;
	int status;

	if (manager == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	region1 = manager->internal.get_region (manager, false);
	prev_valid |= region1->is_valid;
	status = recovery_image_manager_erase_recovery_region (region1);
	if (status != 0) {
		goto exit;
	}

	manager->updating = NULL;

	region2 = manager->internal.get_region (manager, true);
	if (region1 != region2) {
		prev_valid |= region2->is_valid;
		status = recovery_image_manager_erase_recovery_region (region2);
	}

exit:
	platform_mutex_unlock (&manager->lock);
	if (prev_valid) {
		observable_notify_observers (&manager->observable,
			offsetof (struct recovery_image_observer, on_recovery_image_deactivated));
	}
	return status;
}

/**
 * Initialize the recovery image manager that manages a single recovery image flash region.
 *
 * @param manager The manager to initialize.
 * @param image The recovery image instance.
 * @param hash The hash engine to be used for recovery image verification.
 * @param verification The module to be used for recovery image verification.
 * @param pfm The PFM manager to be used for image verification.
 * @param max_size The maximum size for a recovery image.
 *
 * @return 0 if the recovery image manager was initialized successfully or an error code.
 */
int recovery_image_manager_init (struct recovery_image_manager *manager,
	struct recovery_image *image, struct hash_engine *hash,
	struct signature_verification *verification, struct pfm_manager *pfm, size_t max_size)
{
	int status;

	if ((manager == NULL) || (image == NULL) || (hash == NULL) || (verification == NULL) ||
		(pfm == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct recovery_image_manager));

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	manager->region1.image = image;
	manager->hash = hash;
	manager->verification = verification;
	manager->pfm = pfm;

	status = recovery_image_manager_verify_recovery_image (manager, image, &manager->region1, pfm);
	if (status != 0) {
		goto release_observer;
	}

	status = flash_updater_init (&manager->region1.updater, manager->region1.image->flash,
		manager->region1.image->addr, max_size);
	if (status != 0) {
		goto release_observer;
	}

	manager->get_active_recovery_image = recovery_image_manager_get_active_recovery_image;
	manager->clear_recovery_image_region = recovery_image_manager_clear_recovery_image_region;
	manager->free_recovery_image = recovery_image_manager_free_recovery_image;
	manager->write_recovery_image_data = recovery_image_manager_write_recovery_image_data;
	manager->activate_recovery_image = recovery_image_manager_activate_recovery_image;
	manager->get_flash_update_manager = recovery_image_manager_get_flash_update_manager;
	manager->erase_all_recovery_regions = recovery_image_manager_erase_all_recovery_regions;
	manager->internal.get_region = recovery_image_manager_get_region;

	status = platform_mutex_init (&manager->lock);
	if (status != 0) {
		goto release_updater;
	}

	return 0;

release_updater:
	flash_updater_release (&manager->region1.updater);
release_observer:
	observable_release (&manager->observable);
	return status;
}

/**
 * Initialize the recovery image manager that manages two recovery image flash regions. The two
 * flash regions will ping-pong between active and inactive mode.
 *
 * @param manager The manager to initialize.
 * @param image1 The first recovery image instance.
 * @param image2 The second recovery image instance.
 * @param state The host state manager to track the active recovery image region.
 * @param hash The hash engine to be used for recovery image verification.
 * @param verification The module to be used for recovery image verification.
 * @param pfm The PFM manager to be used for image verification.
 * @param max_size The maximum size for a single recovery image region.
 *
 * @return 0 if the recovery image manager was initialized successfully or an error code.
 */
int recovery_image_manager_init_two_region (struct recovery_image_manager *manager,
	struct recovery_image *image1, struct recovery_image *image2, struct host_state_manager *state,
	struct hash_engine *hash, struct signature_verification *verification, struct pfm_manager *pfm,
	size_t max_size)
{
	enum recovery_image_region active_region;
	int status;

	if ((manager == NULL) || (image1 == NULL) || (image2 == NULL) || (state == NULL) ||
		(hash == NULL) || (verification == NULL) || (pfm == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct recovery_image_manager));

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	manager->region1.image = image1;
	manager->region2.image = image2;
	manager->hash = hash;
	manager->verification = verification;
	manager->pfm = pfm;
	manager->state = state;

	active_region = host_state_manager_get_active_recovery_image (state);

	if (active_region == RECOVERY_IMAGE_REGION_1) {
		status = recovery_image_manager_verify_recovery_image (manager, image1, &manager->region1,
			pfm);
	}
	else {
		status = recovery_image_manager_verify_recovery_image (manager, image2, &manager->region2,
			pfm);
	}

	if (status != 0) {
		goto release_observer;
	}

	status = flash_updater_init (&manager->region1.updater, manager->region1.image->flash,
		manager->region1.image->addr, max_size);
	if (status != 0) {
		goto release_observer;
	}

	status = flash_updater_init (&manager->region2.updater, manager->region2.image->flash,
		manager->region2.image->addr, max_size);
	if (status != 0) {
		goto release_updater1;
	}

	manager->get_active_recovery_image = recovery_image_manager_get_active_recovery_image;
	manager->clear_recovery_image_region = recovery_image_manager_clear_recovery_image_region;
	manager->free_recovery_image = recovery_image_manager_free_recovery_image;
	manager->write_recovery_image_data = recovery_image_manager_write_recovery_image_data;
	manager->activate_recovery_image = recovery_image_manager_activate_recovery_image;
	manager->get_flash_update_manager = recovery_image_manager_get_flash_update_manager;
	manager->erase_all_recovery_regions = recovery_image_manager_erase_all_recovery_regions;
	manager->internal.get_region = recovery_image_manager_get_region_two_region;

	status = platform_mutex_init (&manager->lock);
	if (status != 0) {
		goto release_updater2;
	}

	return 0;

release_updater2:
	flash_updater_release (&manager->region2.updater);
release_updater1:
	flash_updater_release (&manager->region1.updater);
release_observer:
	observable_release (&manager->observable);

	return status;
}

/**
 * Release the resources used by the recovery image manager.
 *
 * @param manager The manager to release.
 */
void recovery_image_manager_release (struct recovery_image_manager *manager)
{
	if (manager) {
		observable_release (&manager->observable);
		platform_mutex_free (&manager->lock);
		flash_updater_release (&manager->region1.updater);
		if (manager->region2.image != NULL) {
			flash_updater_release (&manager->region2.updater);
		}
	}
}

/**
 * Set the port identifier for a recovery image manager.
 *
 * @param manager The recovery image manager to configure.
 * @param port The port identifier to set.
 */
void recovery_image_manager_set_port (struct recovery_image_manager *manager, int port)
{
	if (manager) {
		manager->port = port;
	}
}

/**
 * Get the port identifier for a recovery image manager.
 *
 * @param manager The recovery image manager instance to query.
 *
 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int recovery_image_manager_get_port (struct recovery_image_manager *manager)
{
	if (manager) {
		return manager->port;
	}
	else {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}
}

/**
 * Get the data used for recovery image measurement.  The recovery image instance must be released
 * with the manager.
 *
 * @param manager The recovery image manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of recovery image measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int recovery_image_manager_get_measured_data (struct recovery_image_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	uint8_t hash_out[SHA256_HASH_LENGTH] = {0};
	int status = 0;
	struct recovery_image *active;
	size_t bytes_read;

	if ((buffer == NULL) || (manager == NULL) || (total_len == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	*total_len = SHA256_HASH_LENGTH;

	if (offset > (SHA256_HASH_LENGTH - 1)) {
		return 0;
	}

	active = manager->get_active_recovery_image (manager);
	if (active) {
		status = active->get_hash (active, manager->hash, hash_out, sizeof (hash_out));
		manager->free_recovery_image (manager, active);
		if (status != 0) {
			return status;
		}
	}

	bytes_read = min (SHA256_HASH_LENGTH - offset, length);

	memcpy (buffer, hash_out + offset, bytes_read);

	return bytes_read;
}
