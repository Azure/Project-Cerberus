// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_logging.h"
#include "firmware_update.h"
#include "common/unused.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/**
 * Initialize the platform firmware updater.
 *
 * @param updater The updater to initialize.
 * @param state Variable context for the updater.  This must be uninitialized.
 * @param flash The device and address mapping for firmware images.
 * @param context The application context API.
 * @param fw The platform handler for firmware images.
 * @param security The manager for the device security policy.
 * @param hash The hash engine to use during updates.
 * @param allowed_revision The lowest image ID that will be allowed for firmware updates.
 *
 * @return 0 if the updater was successfully initialized or an error code.
 */
int firmware_update_init (struct firmware_update *updater, struct firmware_update_state *state,
	const struct firmware_flash_map *flash, const struct app_context *context,
	const struct firmware_image *fw, const struct security_manager *security,
	struct hash_engine *hash, int allowed_revision)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (updater, 0, sizeof (struct firmware_update));

	updater->state = state;
	updater->flash = flash;
	updater->fw = fw;
	updater->security = security;
	updater->context = context;
	updater->hash = hash;

	return firmware_update_init_state (updater, allowed_revision);
}

/**
 * Initialize the platform firmware updater.
 *
 * Firmware images processed by the updater are not required to contain a firmware header.  If the
 * firmware header is present, it will be processed.  If the firmware header is not present, the
 * update will proceed without it and any workflows that require information from the header will
 * be skipped.
 *
 * @param updater The updater to initialize.
 * @param state Variable context for the updater.  This must be uninitialized.
 * @param flash The device and address mapping for firmware images.
 * @param context The application context API.
 * @param fw The platform handler for firmware images.
 * @param security The manager for the device security policy.
 * @param hash The hash engine to use during updates.
 * @param allowed_revision The lowest image ID that will be allowed for firmware updates.
 *
 * @return 0 if the updater was successfully initialized or an error code.
 */
int firmware_update_init_no_firmware_header (struct firmware_update *updater,
	struct firmware_update_state *state, const struct firmware_flash_map *flash,
	const struct app_context *context, const struct firmware_image *fw,
	const struct security_manager *security, struct hash_engine *hash, int allowed_revision)
{
	int status;

	status = firmware_update_init (updater, state, flash, context, fw, security, hash,
		allowed_revision);
	if (status == 0) {
		updater->no_fw_header = true;
	}

	return status;
}

/**
 * Initialize only the variable state for the platform firmware updater.  The rest of the firmware
 * update instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param updater The updater instance that contains the state to initialize.
 * @param allowed_revision The lowest image ID that will be allowed for firmware updates.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int firmware_update_init_state (const struct firmware_update *updater, int allowed_revision)
{
	int status;

	if ((updater == NULL) || (updater->state == NULL) || (updater->flash == NULL) ||
		(updater->context == NULL) || (updater->fw == NULL) || (updater->security == NULL) ||
		(updater->hash == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if ((updater->flash->active_flash == NULL) || (updater->flash->staging_flash == NULL)) {
		return FIRMWARE_UPDATE_INVALID_FLASH_MAP;
	}

	if ((updater->flash->backup_flash == NULL) && (updater->flash->recovery_flash == NULL)) {
		return FIRMWARE_UPDATE_INVALID_FLASH_MAP;
	}

	memset (updater->state, 0, sizeof (struct firmware_update_state));

	status = flash_updater_init (&updater->state->update_mgr, updater->flash->staging_flash,
		updater->flash->staging_addr, updater->flash->staging_size);
	if (status != 0) {
		return status;
	}

	status = observable_init (&updater->state->observable);
	if (status != 0) {
		flash_updater_release (&updater->state->update_mgr);

		return status;
	}

	updater->state->recovery_rev = -1;
	updater->state->min_rev = allowed_revision;

	return 0;
}

/**
 * Release the resources used by a firmware updater.
 *
 * @param updater The updater to release.
 */
void firmware_update_release (const struct firmware_update *updater)
{
	if (updater) {
		observable_release (&updater->state->observable);
		flash_updater_release (&updater->state->update_mgr);
	}
}

/**
 * Set the offset to apply to each firmware region when writing images.
 *
 * This should be called only during initialization if the updater requires an image offset.
 *
 * @param updater The firmware updater to configure.
 * @param offset The offset to apply to images.
 */
void firmware_update_set_image_offset (const struct firmware_update *updater, int offset)
{
	if (updater != NULL) {
		updater->state->img_offset = offset;
		flash_updater_apply_update_offset (&updater->state->update_mgr, offset);
	}
}

/**
 * Provide the firmware updater with the image ID of the current recovery image.  This ID will be
 * checked during updates to see if the recovery image also needs updating.
 *
 * This should only be used is specific scenarios where forcing a particular recovery revision is
 * necessary.  Generally, firmware_update_validate_recovery_image should be preferred to configure
 * this value.
 *
 * @param updater The firmware updater to configure.
 * @param revision The revision ID of the recovery image.
 */
void firmware_update_set_recovery_revision (const struct firmware_update *updater, int revision)
{
	if (updater != NULL) {
		updater->state->recovery_rev = revision;
	}
}

/**
 * Indicate to the firmware updater if the recovery image on flash is currently good.
 *
 * It is expected that this would be set once during initialization for a system that has a recovery
 * image.  After initialization, the state of the recovery image will be automatically tracked by
 * the updater.  This state will also get set by firmware_update_validate_recovery_image.
 *
 * This can also be used to force the updater to treat the recovery image as bad to trigger recovery
 * update flows that may otherwise not get executed.
 *
 * @param updater The firmware updater to configure.
 * @param img_good Flag indicating if the current recovery image is good.
 */
void firmware_update_set_recovery_good (const struct firmware_update *updater, bool img_good)
{
	if (updater != NULL) {
		updater->state->recovery_bad = !img_good;
	}
}

/**
 * Trigger the notification callback for a firmware update status change.
 *
 * @param callback The notification callback to trigger.
 * @param status The status to notify.
 */
static void firmware_update_status_change (const struct firmware_update_notification *callback,
	enum firmware_update_status status)
{
	if ((callback != NULL) && (callback->status_change != NULL)) {
		callback->status_change (callback, status);
	}
}

/**
 * Load an image context from flash and check if the image is valid.
 *
 * @param updater The updater to use for verification.
 * @param callback Status callback to report status in case of failures.  This can be null to not
 * have status reporting.
 * @param flash The flash device that contains the image to load and verify.
 * @param address Base address of the image.  This does not include any image offset.
 * @param check_bytes Flag indicating if remaining bytes of an active update should be considered
 * during verification.
 * @param boot_image Flag indicating if boot image verification needs to be run.
 * @param check_rollback Flag indicating if recovery revision rollback should be checked.
 * @param img_size Output for the total size of the image.  This is only valid if the image was
 * successfully verified.  This can be null if the image size is not needed.
 * @param recovery_rev Output for the recovery revision from the firmware header.  This is only
 * valid if the image was successfully verified.  If the image does not have a firmware header and
 * one is not required, the value will not be updated.  This can be null if the recovery revision is
 * not needed.
 *
 * @return 0 if the image the image is valid and all required information was retrieved, or an error
 * code.
 */
static int firmware_update_load_and_verify_image (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, const struct flash *flash,
	uint32_t address, bool check_bytes, bool boot_image, bool check_rollback, size_t *img_size,
	int *recovery_rev)
{
	int status;

	firmware_update_status_change (callback, UPDATE_STATUS_VERIFYING_IMAGE);

	if (check_bytes) {
		if (flash_updater_get_remaining_bytes (&updater->state->update_mgr) > 0) {
			firmware_update_status_change (callback, UPDATE_STATUS_INCOMPLETE_IMAGE);

			return FIRMWARE_UPDATE_INCOMPLETE_IMAGE;
		}
	}

	status = updater->fw->load (updater->fw, flash, address + updater->state->img_offset);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);

		return status;
	}

	status = updater->fw->verify (updater->fw, updater->hash);
	if (status != 0) {
		if ((status == FIRMWARE_IMAGE_BAD_SIGNATURE) ||
			(status == FIRMWARE_IMAGE_MANIFEST_REVOKED)) {
			firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);
		}
		else {
			firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);
		}

		return status;
	}

	if (boot_image && updater->internal.verify_boot_image) {
		status = updater->internal.verify_boot_image (updater, flash, address);
		if (status != 0) {
			return status;
		}
	}

	if (img_size) {
		int img_length = updater->fw->get_image_size (updater->fw);

		if (ROT_IS_ERROR (img_length)) {
			firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);

			return img_length;
		}

		*img_size = img_length;
	}

	if (recovery_rev) {
		const struct firmware_header *header = NULL;
		const struct security_policy *policy;
		int img_revision;

		header = updater->fw->get_firmware_header (updater->fw);
		if (header != NULL) {
			status = firmware_header_get_recovery_revision (header, &img_revision);
			if (status != 0) {
				firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);

				return status;
			}

			if (check_rollback) {
				policy = security_manager_get_security_policy (updater->security);

				if (security_policy_enforce_anti_rollback (policy)) {
					if (img_revision < updater->state->min_rev) {
						firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);

						return FIRMWARE_UPDATE_REJECTED_ROLLBACK;
					}
				}
			}

			*recovery_rev = img_revision;
		}
		else if (!updater->no_fw_header) {
			firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);

			return FIRMWARE_UPDATE_NO_FIRMWARE_HEADER;
		}
	}

	return 0;
}

/**
 * Set the updater state of the recovery image by actively reading the flash contents.  If the
 * updater is not configured to use a recovery image, no operation is performed.
 *
 * If there is a valid recovery image, the revision of the recovery image will be cached for use
 * during updates.  There is no need to call firmware_update_set_recovery_revision.
 *
 * If there is an error while trying to determine the validity of the recovery image, the internal
 * state will be updated as if the recovery image is bad.  This will ensure that updates proceed
 * only if it knows a good recovery image exists.
 *
 * @param updater The updater to configure.
 */
void firmware_update_validate_recovery_image (const struct firmware_update *updater)
{
	int status;

	if (updater == NULL) {
		return;
	}

	if (updater->flash->recovery_flash) {
		status = firmware_update_load_and_verify_image (updater, NULL,
			updater->flash->recovery_flash, updater->flash->recovery_addr, false, true, false, NULL,
			&updater->state->recovery_rev);

		updater->state->recovery_bad = (status != 0);
		debug_log_create_entry ((updater->state->recovery_bad) ? DEBUG_LOG_SEVERITY_WARNING :
				DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_RECOVERY_IMAGE, updater->state->recovery_bad, status);
	}
}

/**
 * Indicate if the recovery image on flash is currently good.
 *
 * @param updater The firmware updater to query.
 *
 * @return 1 if the recovery image is good, 0 if the recovery image is bad, or an error code.
 */
int firmware_update_is_recovery_good (const struct firmware_update *updater)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return updater->state->recovery_bad ? 0 : 1;
}

/**
 * Program a bootable region of flash with a new image.
 *
 * @param updater The updater to use for programming.
 * @param dest The bootable flash device to program.
 * @param dest_addr The address program the image to.
 * @param src The flash device with the image to copy to the bootable region.
 * @param src_addr The starting address of the new image.
 * @param length The length of the new image.
 * @param page The page size of flash being written.
 *
 * @return 0 if the new image was copied successfully to the active region or an error code.
 */
static int firmware_update_program_bootable (const struct firmware_update *updater,
	const struct flash *dest, uint32_t dest_addr, const struct flash *src, uint32_t src_addr,
	size_t length, uint32_t page)
{
	int status;

	UNUSED (updater);

	if (length > page) {
		status = flash_copy_ext_to_blank_and_verify (dest, dest_addr + page, src, src_addr + page,
			length - page);
		if (status == 0) {
			status = flash_copy_ext_to_blank_and_verify (dest, dest_addr, src, src_addr, page);
		}
	}
	else {
		status = flash_copy_ext_to_blank_and_verify (dest, dest_addr, src, src_addr, length);
	}

	return status;
}

/**
 * Call the internal updater function to finalize an image installation.
 *
 * @param updater The updater instance.
 * @param flash The flash that has the new image.
 * @param address The base address for the image region.
 *
 * @return 0 if the image was successfully finalized or an error code.
 */
static int firmware_update_finalize_image (const struct firmware_update *updater,
	const struct flash *flash, uint32_t address)
{
	if (updater->internal.finalize_image) {
		return updater->internal.finalize_image (updater, flash, address);
	}

	return 0;
}

/**
 * Write a new firmware image to a region in flash from the staging region.
 *
 * The image currently in flash will optionally be backed up.  If there is an error writing the new
 * image, an attempt will be made to restore the current image from the backup.
 *
 * @param updater The updater being executed.
 * @param callback The updated notification handlers.
 * @param dest The destination flash device for the new image.
 * @param dest_addr The destination address for the new image.
 * @param backup The backup flash device.  This can be null to not create a backup.
 * @param backup_addr The address to store the backup.
 * @param src The source flash device that contains the new image.
 * @param src_addr The source address of the new image.
 * @param update_len The length of the new image.
 * @param backup_start The status to report when image backup has started.
 * @param backup_fail The status to report if image backup has failed.
 * @param update_start The status to report when the image has started update.
 * @param update_fail The status to report if the image update failed.
 * @param img_good Optional output indicating of the destination region contains a good image at the
 * end of this process.  It does not mean the new image is in the region, just that there is a good
 * one, such as when a backup image is restored in error handling.
 *
 * @return 0 if the new firmware image was successfully written or an error code.
 */
static int firmware_update_write_image (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, const struct flash *dest,
	uint32_t dest_addr, const struct flash *backup, uint32_t backup_addr, const struct flash *src,
	uint32_t src_addr, size_t update_len, enum firmware_update_status backup_start,
	enum firmware_update_status backup_fail, enum firmware_update_status update_start,
	enum firmware_update_status update_fail, bool *img_good)
{
	int backup_len = 0;
	uint32_t page;
	int status;

	if (img_good) {
		*img_good = true;
	}

	if (backup) {
		/* Backup the current image. */
		firmware_update_status_change (callback, backup_start);
		status = updater->fw->load (updater->fw, dest, dest_addr + updater->state->img_offset);
		if (status != 0) {
			firmware_update_status_change (callback, backup_fail);

			return status;
		}

		backup_len = updater->fw->get_image_size (updater->fw);
		if (ROT_IS_ERROR (backup_len)) {
			firmware_update_status_change (callback, backup_fail);

			return backup_len;
		}

		status = flash_copy_ext_and_verify (backup, backup_addr + updater->state->img_offset, dest,
			dest_addr + updater->state->img_offset, backup_len);
		if (status != 0) {
			firmware_update_status_change (callback, backup_fail);

			return status;
		}
	}

	/* Update the new image from staging flash. */
	firmware_update_status_change (callback, update_start);

	status = dest->get_page_size (dest, &page);
	if (status != 0) {
		firmware_update_status_change (callback, update_fail);

		return status;
	}

	if (img_good) {
		*img_good = false;
	}

	status = flash_erase_region_and_verify (dest, dest_addr,
		update_len + updater->state->img_offset);
	if (status != 0) {
		firmware_update_status_change (callback, update_fail);

		return status;
	}

	status = firmware_update_program_bootable (updater, dest,
		dest_addr + updater->state->img_offset, src, src_addr + updater->state->img_offset,
		update_len, page);
	if (status == 0) {
		status = firmware_update_finalize_image (updater, dest, dest_addr);
	}

	if (status != 0) {
		if (backup) {
			/* Try to restore the image that was backed up. */
			if (flash_erase_region_and_verify (dest, dest_addr,
				backup_len + updater->state->img_offset) == 0) {
				if (firmware_update_program_bootable (updater, dest,
					dest_addr + updater->state->img_offset, backup,
					backup_addr + updater->state->img_offset, backup_len, page) == 0) {
					if (firmware_update_finalize_image (updater, dest, dest_addr) == 0) {
						*img_good = true;
					}
				}
			}
		}

		firmware_update_status_change (callback, update_fail);

		return status;
	}

	if (img_good) {
		*img_good = true;
	}

	return 0;
}

/**
 * Restore an image from one flash region to another.
 *
 * @param updater The updater to use for image restoration.
 * @param dest The flash device to restore to.
 * @param dest_addr The address to restore the image to.
 * @param src The flash device with the image to restore from.
 * @param src_addr The address to restore from.
 * @param src_valid Optional output parameter indicating if the failure was due to an invalid source
 * image.
 * @param recovery_rev Optional output parameter for the recovery revision for the image that was
 * restored.
 *
 * @return 0 if image was successfully restored or an error code.
 */
static int firmware_update_restore_image (const struct firmware_update *updater,
	const struct flash *dest, uint32_t dest_addr, const struct flash *src, uint32_t src_addr,
	bool *src_invalid, int *recovery_rev)
{
	size_t img_len = 0;
	int status;

	if (src_invalid) {
		*src_invalid = true;
	}

	status = firmware_update_load_and_verify_image (updater, NULL, src, src_addr, false, false,
		false, &img_len, recovery_rev);
	if (status != 0) {
		return status;
	}

	if (src_invalid) {
		*src_invalid = false;
	}

	/* Enum values for the firmware_update_status are not relevant since the callback will always be
	 * null for this call. */
	return firmware_update_write_image (updater, NULL, dest, dest_addr, NULL, 0, src, src_addr,
		img_len, UPDATE_STATUS_SUCCESS, UPDATE_STATUS_SUCCESS, UPDATE_STATUS_SUCCESS,
		UPDATE_STATUS_SUCCESS, NULL);
}

/**
 * Use the active image to restore a corrupt recovery image.  Only if the recovery image is known to
 * be bad will anything be changed.
 *
 * @param updater The updater to use for the image restore operation.
 * @param active_invalid Optional output parameter indicating if the failure is due to the active
 * image not being valid.
 *
 * @return 0 if the recovery image was restored successfully or an error code.  If the recovery
 * image is already good, FIRMWARE_UPDATE_RESTORE_NOT_NEEDED will be returned.
 */
static int firmware_update_restore_recovery_image_error_detail (
	const struct firmware_update *updater, bool *active_invalid)
{
	int status = FIRMWARE_UPDATE_NO_RECOVERY_IMAGE;
	int recovery_rev = -1;

	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (updater->flash->recovery_flash) {
		if (updater->state->recovery_bad) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_RESTORE_START, 0, 0);

			status = firmware_update_restore_image (updater, updater->flash->recovery_flash,
				updater->flash->recovery_addr, updater->flash->active_flash,
				updater->flash->active_addr, active_invalid, &recovery_rev);
			if (status == 0) {
				updater->state->recovery_bad = false;
				updater->state->recovery_rev = recovery_rev;

				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_RECOVERY_IMAGE, 0, 0);
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_RECOVERY_RESTORE_FAIL, status, 0);
			}
		}
		else {
			status = FIRMWARE_UPDATE_RESTORE_NOT_NEEDED;
		}
	}

	return status;
}

/**
 * Use the active image to restore a corrupt recovery image.  Only if the recovery image is known to
 * be bad will anything be changed.
 *
 * @param updater The updater to use for the image restore operation.
 *
 * @return 0 if the recovery image was restored successfully or an error code.  If the recovery
 * image is already good, FIRMWARE_UPDATE_RESTORE_NOT_NEEDED will be returned.
 */
int firmware_update_restore_recovery_image (const struct firmware_update *updater)
{
	return firmware_update_restore_recovery_image_error_detail (updater, NULL);
}

/**
 * Use the recovery image to restore the active image.  The state of the active image is not checked
 * before updating it with the recovery image.
 *
 * @param updater The updater to use for the image restore operation.
 *
 * @return 0 if the active image was restored successfully or an error code.  The result is returned
 * in case the caller needs this information, but the result of the operation will have already been
 * logged.
 */
int firmware_update_restore_active_image (const struct firmware_update *updater)
{
	int status;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
		FIRMWARE_LOGGING_ACTIVE_RESTORE_START, 0, 0);

	if (updater == NULL) {
		status = FIRMWARE_UPDATE_INVALID_ARGUMENT;
		goto done;
	}

	if (updater->flash->recovery_flash) {
		status = firmware_update_restore_image (updater, updater->flash->active_flash,
			updater->flash->active_addr, updater->flash->recovery_flash,
			updater->flash->recovery_addr, NULL, NULL);
	}
	else {
		status = FIRMWARE_UPDATE_NO_RECOVERY_IMAGE;
	}

done:
	debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
		DEBUG_LOG_COMPONENT_CERBERUS_FW, FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE, status, 0);

	return status;
}

/**
 * Determine if the contents of the recovery flash exactly match the contents of the active flash.
 * This does no verification of either image and only parses enough to make the comparison.  If the
 * updater is not configured to use a recovery image, the call reports a match.
 *
 * @param updater The firmware updater to use for the comparison.
 *
 * @return 0 if the images exactly match, 1 if they don't, or an error code.
 */
int firmware_update_recovery_matches_active_image (const struct firmware_update *updater)
{
	int active_len;
	int recovery_len;
	int status = 0;

	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (updater->flash->recovery_flash) {
		status = updater->fw->load (updater->fw, updater->flash->active_flash,
			updater->flash->active_addr + updater->state->img_offset);
		if (status != 0) {
			return status;
		}

		active_len = updater->fw->get_image_size (updater->fw);
		if (ROT_IS_ERROR (active_len)) {
			return active_len;
		}

		status = updater->fw->load (updater->fw, updater->flash->recovery_flash,
			updater->flash->recovery_addr + updater->state->img_offset);
		if (status != 0) {
			return status;
		}

		recovery_len = updater->fw->get_image_size (updater->fw);
		if (ROT_IS_ERROR (recovery_len)) {
			return recovery_len;
		}

		/* If the images are not the same length, no point in checking the flash contents. */
		if (active_len != recovery_len) {
			return 1;
		}

		status = flash_verify_copy_ext (updater->flash->active_flash,
			updater->flash->active_addr + updater->state->img_offset,
			updater->flash->recovery_flash,
			updater->flash->recovery_addr + updater->state->img_offset, active_len);
		if ((status != 0) && (status != FLASH_UTIL_DATA_MISMATCH)) {
			return status;
		}
	}

	return (status == 0) ? 0 : 1;
}

/**
 * Add an observer for firmware update notifications.
 *
 * @param updater The firmware updater to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int firmware_update_add_observer (const struct firmware_update *updater,
	const struct firmware_update_observer *observer)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return observable_add_observer (&updater->state->observable, (void*) observer);
}

/**
 * Remove an observer from firmware update notifications.
 *
 * @param updater The firmware updater to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int firmware_update_remove_observer (const struct firmware_update *updater,
	const struct firmware_update_observer *observer)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&updater->state->observable, (void*) observer);
}

/**
 * Copy the image from staging flash to active flash.
 *
 * @param updater The updater to execute.
 * @param callback Status callback to report status updates.  This can be null to not have status
 * reporting.
 * @param img_length Length of the image in staging flash.
 * @param recovery_updated Output indicating if the recovery image was also updated.  This can be
 * null if this information is not needed.
 *
 * @return 0 if active flash was successfully updated or an error code.
 */
static int firmware_update_apply_update (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, size_t img_length, bool *recovery_updated)
{
	bool img_good;
	int allow_update;
	int status;

	/* Notify the system of an update and see if it should be allowed. */
	allow_update = 0;
	observable_notify_observers_with_ptr (&updater->state->observable,
		offsetof (struct firmware_update_observer, on_update_start), &allow_update);
	if (allow_update != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_SYSTEM_PREREQ_FAIL);

		return allow_update;
	}

	/* Save the running application context to restore after reboot. */
	firmware_update_status_change (callback, UPDATE_STATUS_SAVING_STATE);
	status = updater->context->save (updater->context);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_STATE_SAVE_FAIL);

		return status;
	}

	/* Don't allow the active image to be erased until we have a good recovery image. */
	if (updater->flash->recovery_flash && updater->state->recovery_bad) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_RECOVERY_UPDATE, 0, 0);
		debug_log_flush ();

		status = firmware_update_write_image (updater, callback, updater->flash->recovery_flash,
			updater->flash->recovery_addr, NULL, 0, updater->flash->staging_flash,
			updater->flash->staging_addr, img_length, UPDATE_STATUS_BACKUP_RECOVERY,
			UPDATE_STATUS_BACKUP_REC_FAIL, UPDATE_STATUS_UPDATE_RECOVERY,
			UPDATE_STATUS_UPDATE_REC_FAIL, &img_good);
		if (status != 0) {
			return status;
		}

		updater->state->recovery_bad = !img_good;
		if (recovery_updated) {
			*recovery_updated = true;
		}
	}

	/* Update the active image from staging flash. */
	return firmware_update_write_image (updater, callback, updater->flash->active_flash,
		updater->flash->active_addr, updater->flash->backup_flash, updater->flash->backup_addr,
		updater->flash->staging_flash, updater->flash->staging_addr, img_length,
		UPDATE_STATUS_BACKUP_ACTIVE, UPDATE_STATUS_BACKUP_FAILED, UPDATE_STATUS_UPDATING_IMAGE,
		UPDATE_STATUS_UPDATE_FAILED, &img_good);
}

/**
 * Check for manifest revocation based on the loaded firmware image.  If revocation is indicated,
 * process the revocation by updating the recovery image and updated the device state.
 *
 * This will also update the recovery image when necessary, even if the manifest has not been
 * revoked.
 *
 * @param updater The updater to use for revocation processing.
 * @param callback Status callback to report status updates.  This can be null to not have status
 * reporting.
 * @param flash The flash device containing the image to use for recovery updates.
 * @param address Base address of the image to use for recovery updates.
 * @param img_length Length of the image to use for recovery updates.
 * @param new_revision The recovery revision of the loaded image.
 * @param recovery_updated Flag indicating if the recovery image has already been updated.
 *
 * @return 0 if revocation was processed successfully or an error code.
 */
static int firmware_update_process_manifest_revocation (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, const struct flash *flash,
	uint32_t address, size_t img_length, int new_revision, bool recovery_updated)
{
	const struct key_manifest *manifest;
	bool img_good;
	int manifest_revoked;
	int status;

	manifest = updater->fw->get_key_manifest (updater->fw);
	if (manifest == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);

		return FIRMWARE_UPDATE_NO_KEY_MANIFEST;
	}

	manifest_revoked = manifest->revokes_old_manifest (manifest);
	if (ROT_IS_ERROR (manifest_revoked)) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);

		return manifest_revoked;
	}

	/* Check if recovery update is necessary. */
	firmware_update_status_change (callback, UPDATE_STATUS_CHECK_RECOVERY);
	if (manifest_revoked || updater->state->recovery_bad ||
		(updater->state->recovery_rev != new_revision)) {
		if (updater->flash->recovery_flash && !recovery_updated) {
			const struct flash *backup = NULL;
			uint32_t backup_addr = 0;

			if (!updater->state->recovery_bad) {
				if (updater->flash->rec_backup_flash) {
					backup = updater->flash->rec_backup_flash;
					backup_addr = updater->flash->rec_backup_addr;
				}
				else {
					backup = updater->flash->backup_flash;
					backup_addr = updater->flash->backup_addr;
				}
			}

			/* Update the recovery image from staging flash. */
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_UPDATE, 0, 0);
			debug_log_flush ();

			status = firmware_update_write_image (updater, callback, updater->flash->recovery_flash,
				updater->flash->recovery_addr, backup, backup_addr, flash, address, img_length,
				UPDATE_STATUS_BACKUP_RECOVERY, UPDATE_STATUS_BACKUP_REC_FAIL,
				UPDATE_STATUS_UPDATE_RECOVERY, UPDATE_STATUS_UPDATE_REC_FAIL, &img_good);

			updater->state->recovery_bad = !img_good;
			if (status != 0) {
				return status;
			}
		}

		updater->state->recovery_rev = new_revision;

		if (manifest_revoked) {
			/* Revoke the old manifest. */
			firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_MANIFEST);

			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_REVOCATION_UPDATE, 0, 0);
			debug_log_flush ();

			status = manifest->update_revocation (manifest);
			if (status != 0) {
				firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_FAILED);

				return status;
			}
		}
	}

	return 0;
}

/**
 * Run the firmware update process.  The firmware update will take the following steps:
 * 		- Validate the data store in the staging flash region to ensure a good image.
 * 		- Save the application state that should be restored after the update.
 * 		- Copy the image in staging flash to active flash, taking a backup if configured to do so.
 * 		- Copy the image in staging flash to recovery flash, taking a backup if configured to do so,
 * 			if the recovery manifest has been revoked, the recovery revision has changed, or the
 * 			recovery image is known to be bad.
 * 		- Update manifest revocation information in the device.
 *
 * @param updater The updater that should run.
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return 0 if the update completed successfully or an error code.
 */
int firmware_update_run_update (const struct firmware_update *updater,
	const struct firmware_update_notification *callback)
{
	bool recovery_updated = false;
	size_t new_len = 0;
	int new_revision;
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_START_FAILURE);

		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	/* If there is no FW header on the image, just apply the updater's recovery revision to the new
	 * image.  Without a FW header, the recovery image will only get updated during manifest
	 * revocation flows. */
	new_revision = updater->state->recovery_rev;

	/* Verify image in staging flash. */
	status = firmware_update_load_and_verify_image (updater, callback,
		updater->flash->staging_flash, updater->flash->staging_addr, true, false, true, &new_len,
		&new_revision);
	if (status != 0) {
		return status;
	}

	/* Apply the update to active flash. */
	status = firmware_update_apply_update (updater, callback, new_len, &recovery_updated);
	if (status != 0) {
		return status;
	}

	/* Check for manifest revocation. */
	firmware_update_status_change (callback, UPDATE_STATUS_CHECK_REVOCATION);
	status = updater->fw->load (updater->fw, updater->flash->active_flash,
		updater->flash->active_addr + updater->state->img_offset);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);

		return status;
	}

	status = firmware_update_process_manifest_revocation (updater, callback,
		updater->flash->staging_flash, updater->flash->staging_addr, new_len, new_revision,
		recovery_updated);
	if (status != 0) {
		return status;
	}

	/* Update completed successfully. */
	observable_notify_observers (&updater->state->observable,
		offsetof (struct firmware_update_observer, on_update_applied));

	return 0;
}

/**
 * Run the firmware update process.  Only the active image will be updated as part of the process.
 * The recovery flash will only be modified if the contents are known to be bad.  No revocation
 * flows will be executed.
 *
 * The firmware update will take the following steps:
 * 		- Validate the data store in the staging flash region to ensure a good image.
 * 		- Save the application state that should be restored after the update.
 * 		- If the recovery flash contains an invalid image, copy the current image in active flash to
 * 			recovery flash.  If the current active flash does not contain a valid image, the
 * 			recovery flash will be updated from the image in staging flash.
 * 		- Copy the image in staging flash to active flash, taking a backup if configured to do so.
 *
 * @param updater The updater that should run.
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return 0 if the update completed successfully or an error code.
 */
int firmware_update_run_update_no_revocation (const struct firmware_update *updater,
	const struct firmware_update_notification *callback)
{
	size_t new_len = 0;
	int new_revision;
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_START_FAILURE);

		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	/* If the recovery image is bad, restore it from the active flash before running the update. */
	if (updater->flash->recovery_flash && updater->state->recovery_bad) {
		bool active_invalid = false;

		firmware_update_status_change (callback, UPDATE_STATUS_UPDATE_RECOVERY);

		status = firmware_update_restore_recovery_image_error_detail (updater, &active_invalid);
		debug_log_flush ();
		if ((status != 0) && !active_invalid) {
			/* If the recovery image could not be restored but the active image is good, fail the
			 * update process. */
			firmware_update_status_change (callback, UPDATE_STATUS_UPDATE_REC_FAIL);

			return status;
		}
	}

	/* Verify image in staging flash. */
	status = firmware_update_load_and_verify_image (updater, callback,
		updater->flash->staging_flash, updater->flash->staging_addr, true, false, true, &new_len,
		&new_revision);
	if (status != 0) {
		return status;
	}

	/* Apply the update to active flash. */
	status = firmware_update_apply_update (updater, callback, new_len, NULL);
	if (status != 0) {
		return status;
	}

	/* Update completed successfully. */
	observable_notify_observers (&updater->state->observable,
		offsetof (struct firmware_update_observer, on_update_applied));

	return 0;
}

/**
 * Execute firmware image revocation based on the image stored in active flash.  The revocation
 * process involves the following checks:
 * 		- If the recovery image is known to be bad, copy the active flash image to recovery flash.
 * 		- If the image manifest has been revoked, copy the active flash image to recovery flash and
 * 			update the revocation state within the device.
 * 		- If the firmware header indicates an changed recovery revision, copy the active flash image
 * 			to recovery flash.
 *
 * If none of the checks match the current device state, the function will succeed without doing any
 * operation.
 *
 * @param updater The updater that should execute.
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return 0 if revocation updates were successful or an error code.
 */
int firmware_update_run_revocation (const struct firmware_update *updater,
	const struct firmware_update_notification *callback)
{
	size_t new_len = 0;
	int new_revision;
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_START_FAILURE);

		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	/* If there is no FW header on the image, just apply the updater's recovery revision to the new
	 * image.  Without a FW header, the recovery image will only get updated during manifest
	 * revocation flows. */
	new_revision = updater->state->recovery_rev;

	/* Verify image in active flash. */
	status = firmware_update_load_and_verify_image (updater, callback, updater->flash->active_flash,
		updater->flash->active_addr, false, false, false, &new_len,	&new_revision);
	if (status != 0) {
		return status;
	}

	/* Check for manifest revocation. */
	firmware_update_status_change (callback, UPDATE_STATUS_CHECK_REVOCATION);

	return firmware_update_process_manifest_revocation (updater, callback,
		updater->flash->active_flash, updater->flash->active_addr, new_len, new_revision, false);
}

/**
 * Prepare staging area for incoming FW update file
 *
 * @param updater Updater to use
 * @param size FW update file size to clear in staging area
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return Preparation status, 0 if success or an error code.
 */
int firmware_update_prepare_staging (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, size_t size)
{
	int allow_update = 0;
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP_FAIL);

		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP);

	/* Notify the system than an update is being prepared and see if it should be allowed. */
	observable_notify_observers_with_ptr (&updater->state->observable,
		offsetof (struct firmware_update_observer, on_prepare_update), &allow_update);
	if (allow_update != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP_FAIL);

		return allow_update;
	}

	status = flash_updater_prepare_for_update (&updater->state->update_mgr, size);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP_FAIL);
	}

	return status;
}

/**
 * Program FW update data to staging area
 *
 * @param updater Updater to use
 * @param buf Buffer with FW update data to program
 * @param buf_len Length of FW update data buffer
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return Programming status, 0 if success or an error code.
 */
int firmware_update_write_to_staging (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, uint8_t *buf, size_t buf_len)
{
	int status;

	if ((updater == NULL) || (buf == NULL)) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_WRITE_FAIL);

		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	firmware_update_status_change (callback, UPDATE_STATUS_STAGING_WRITE);

	status = flash_updater_write_update_data (&updater->state->update_mgr, buf, buf_len);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_WRITE_FAIL);
	}

	return status;
}

/**
 * Get the number of bytes remaining in the firmware update currently being received.
 *
 * @param updater The firmware updater to query.
 *
 * @return The number of bytes remaining in the current update.  This can be negative if more bytes
 * have been received than were expected.
 */
int firmware_update_get_update_remaining (const struct firmware_update *updater)
{
	if (updater == NULL) {
		return 0;
	}

	return flash_updater_get_remaining_bytes (&updater->state->update_mgr);
}
