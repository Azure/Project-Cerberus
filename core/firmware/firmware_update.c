// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_update.h"
#include "firmware_logging.h"
#include "flash/flash_util.h"
#include "flash/flash_common.h"


/**
 * Initialize the platform firmware updater.
 *
 * @param updater The updater to initialize.
 * @param flash The device and address mapping for firmware images.
 * @param context The application context API.
 * @param fw The platform handler for firmware images.
 * @param hash The hash engine to use during updates.
 * @param rsa The RSA engine to use for signature verification.
 * @param allowed_revision The lowest image ID that will be allowed for firmware updates.
 *
 * @return 0 if the updater was successfully initialized or an error code.
 */
int firmware_update_init (struct firmware_update *updater, const struct firmware_flash_map *flash,
	struct app_context *context, struct firmware_image *fw, struct hash_engine *hash,
	struct rsa_engine *rsa, int allowed_revision)
{
	int status;

	if ((updater == NULL) || (flash == NULL) || (context == NULL) || (fw == NULL) ||
		(hash == NULL) || (rsa == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if ((flash->active_flash == NULL) || (flash->staging_flash == NULL)) {
		return FIRMWARE_UPDATE_INVALID_FLASH_MAP;
	}

	if ((flash->backup_flash == NULL) && (flash->recovery_flash == NULL)) {
		return FIRMWARE_UPDATE_INVALID_FLASH_MAP;
	}

	memset (updater, 0, sizeof (struct firmware_update));

	status = flash_updater_init (&updater->update_mgr, flash->staging_flash, flash->staging_addr,
		flash->staging_size);
	if (status != 0) {
		return status;
	}

	status = observable_init (&updater->observable);
	if (status != 0) {
		flash_updater_release (&updater->update_mgr);
		return status;
	}

	updater->flash = flash;
	updater->fw = fw;
	updater->context = context;
	updater->hash = hash;
	updater->rsa = rsa;
	updater->recovery_rev = -1;
	updater->min_rev = allowed_revision;

	return 0;
}

/**
 * Release the resources used by a firmware updater.
 *
 * @param updater The updater to release.
 */
void firmware_update_release (struct firmware_update *updater)
{
	if (updater) {
		observable_release (&updater->observable);
		flash_updater_release (&updater->update_mgr);
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
void firmware_update_set_image_offset (struct firmware_update *updater, int offset)
{
	if (updater != NULL) {
		updater->img_offset = offset;
		flash_updater_apply_update_offset (&updater->update_mgr, offset);
	}
}

/**
 * Indicate to the firmware updater if the recovery image on flash is currently good.
 *
 * It is expected that this would be set once during initialization for a system that has a recovery
 * image.  After initialization, the state of the recovery image will be automatically tracked by
 * the updater.
 *
 * @param updater The firmware updater to configure.
 * @param img_good Flag indicating if the current recovery image is good.
 */
void firmware_update_set_recovery_good (struct firmware_update *updater, bool img_good)
{
	if (updater != NULL) {
		updater->recovery_bad = !img_good;
	}
}

/**
 * Provide the firmware updater with the image ID of the current recovery image.  This ID will be
 * checked during updates to see if the recovery image also needs updating.
 *
 * @param updater The firmware updater to configure.
 * @param revision The revision ID of the recovery image.
 */
void firmware_update_set_recovery_revision (struct firmware_update *updater, int revision)
{
	if (updater != NULL) {
		updater->recovery_rev = revision;
	}
}

/**
 * Set the updater state of the recovery image by actively reading the flash contents.  If the
 * updater is not configured to use a recovery image, no operation is performed.
 *
 * If there is an error while trying to determine the validity of the recovery image, the internal
 * state will be updated as if the recovery image is bad.  This will ensure that updates proceed
 * only if it knows a good recovery image exists.
 *
 * @param updater The updater to configure.
 *
 * @return 0 if the operation completed successfully or an error code.  A successful return only
 * means that the updater was able to determine if the recovery was good or not.  It doesn't
 * indicate the validity of the image.
 */
int firmware_update_validate_recovery_image (struct firmware_update *updater)
{
	int status = 0;

	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (updater->flash->recovery_flash) {
		status = updater->fw->load (updater->fw, updater->flash->recovery_flash,
			updater->flash->recovery_addr + updater->img_offset);

		if (status == 0) {
			status = updater->fw->verify (updater->fw, updater->hash, updater->rsa);

			if (updater->internal.verify_boot_image && (status == 0)) {
				status = updater->internal.verify_boot_image (updater,
					updater->flash->recovery_flash, updater->flash->recovery_addr);
			}

			if (status == 0) {
				struct firmware_header *header;

				header = updater->fw->get_firmware_header (updater->fw);
				if (header != NULL) {
					status = firmware_header_get_recovery_revision (header, &updater->recovery_rev);
				}
				else {
					status = FIRMWARE_UPDATE_NO_FIRMWARE_HEADER;
				}
			}
		}
	}

	updater->recovery_bad = (status != 0);
	debug_log_create_entry (
		(updater->recovery_bad) ? DEBUG_LOG_SEVERITY_WARNING : DEBUG_LOG_SEVERITY_INFO,
		DEBUG_LOG_COMPONENT_CERBERUS_FW, FIRMWARE_LOGGING_RECOVERY_IMAGE, updater->recovery_bad,
		status);

	/* TODO:  What about ECC signature errors or revocation checks fails?  This seems generally
	 * fragile.  Maybe we should get rid of it, along with the list of validation codes documented
	 * on firmware_image.load.  That seems like it could become incomplete.
	 *
	 * A better approach is probably to just swallow all errors (maybe change this to return void?).
	 * We already log it and mark the recovery as bad in all error cases.  It's not clear what
	 * benefit there is from the distinction of errors here. */
	if ((status == FIRMWARE_IMAGE_INVALID_FORMAT) || (status == FIRMWARE_IMAGE_BAD_CHECKSUM) ||
		(status == KEY_MANIFEST_INVALID_FORMAT) || (status == RSA_ENGINE_BAD_SIGNATURE) ||
		(status == FIRMWARE_HEADER_BAD_FORMAT_LENGTH) ||
		((status >= IMAGE_HEADER_NOT_MINIMUM_SIZE) && (status <= IMAGE_HEADER_TOO_LONG))) {
		status = 0;
	}
	return ROT_IS_ERROR (status) ? status : 0;
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
static int firmware_update_program_bootable (struct firmware_update *updater, struct flash *dest,
	uint32_t dest_addr, struct flash *src, uint32_t src_addr, size_t length, uint32_t page)
{
	int status;

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
static int firmware_update_finalize_image (struct firmware_update *updater, struct flash *flash,
	uint32_t address)
{
	if (updater->internal.finalize_image) {
		return updater->internal.finalize_image (updater, flash, address);
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
 *
 * @return 0 if image was successfully restored or an error code.
 */
static int firmware_update_restore_image (struct firmware_update *updater, struct flash *dest,
	uint32_t dest_addr, struct flash *src, uint32_t src_addr)
{
	int img_len;
	uint32_t page;
	int status;

	status = updater->fw->load (updater->fw, src, src_addr + updater->img_offset);
	if (status != 0) {
		return status;
	}

	status = updater->fw->verify (updater->fw, updater->hash, updater->rsa);
	if (status != 0) {
		return status;
	}

	img_len = updater->fw->get_image_size (updater->fw);
	if (ROT_IS_ERROR (img_len)) {
		return img_len;
	}

	status = dest->get_page_size (dest, &page);
	if (status != 0) {
		return status;
	}

	status = flash_erase_region_and_verify (dest, dest_addr + updater->img_offset, img_len);
	if (status != 0) {
		return status;
	}

	status = firmware_update_program_bootable (updater, dest, dest_addr + updater->img_offset, src,
		src_addr + updater->img_offset, img_len, page);
	if (status != 0) {
		return status;
	}

	return firmware_update_finalize_image (updater, dest, dest_addr);
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
int firmware_update_restore_recovery_image (struct firmware_update *updater)
{
	int status = FIRMWARE_UPDATE_NO_RECOVERY_IMAGE;
	struct firmware_header *header = NULL;

	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (updater->flash->recovery_flash) {
		if (updater->recovery_bad) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_RESTORE_START, 0, 0);

			status = firmware_update_restore_image (updater, updater->flash->recovery_flash,
				updater->flash->recovery_addr, updater->flash->active_flash,
				updater->flash->active_addr);
			if (status == 0) {
				updater->recovery_bad = false;

				header = updater->fw->get_firmware_header (updater->fw);
				if (header == NULL) {
					firmware_update_set_recovery_revision (updater, -1);
				}
				else {
					firmware_header_get_recovery_revision (header, &updater->recovery_rev);
				}
			}
		}
		else {
			status = FIRMWARE_UPDATE_RESTORE_NOT_NEEDED;
		}
	}

	return status;
}

/**
 * Use the recovery image to restore the active image.  The state of the active image is not checked
 * before updating it with the recovery image.
 *
 * @param updater The updater to use for the image restore operation.
 *
 * @return 0 if the active image was restored successfully or an error code.
 */
int firmware_update_restore_active_image (struct firmware_update *updater)
{
	int status = FIRMWARE_UPDATE_NO_RECOVERY_IMAGE;

	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (updater->flash->recovery_flash) {
		status = firmware_update_restore_image (updater, updater->flash->active_flash,
			updater->flash->active_addr, updater->flash->recovery_flash,
			updater->flash->recovery_addr);
	}

	return status;
}

/**
 * Indicate if the recovery image on flash is currently good.
 *
 * @param updater The firmware updater to query.
 *
 * @return 1 if the recovery image is good, 0 if the recovery image is bad, or an error code.
 */
int firmware_update_is_recovery_good (struct firmware_update *updater)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return updater->recovery_bad ? 0 : 1;
}

/**
 * Add an observer for firmware update notifications.
 *
 * @param updater The firmware updater to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int firmware_update_add_observer (struct firmware_update *updater,
	struct firmware_update_observer *observer)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return observable_add_observer (&updater->observable, observer);
}

/**
 * Remove an observer from firmware update notifications.
 *
 * @param updater The firmware updater to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int firmware_update_remove_observer (struct firmware_update *updater,
	struct firmware_update_observer *observer)
{
	if (updater == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&updater->observable, observer);
}

/**
 * Trigger the notification callback for a firmware update status change.
 *
 * @param callback The notification callback to trigger.
 * @param status The status to notify.
 */
static void firmware_update_status_change (struct firmware_update_notification *callback,
	enum firmware_update_status status)
{
	if ((callback != NULL) && (callback->status_change != NULL)) {
		callback->status_change (callback, status);
	}
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
 * @param update_len The length of the new image.
 * @param backup_start The status to report when image backup has started.
 * @param backup_fail The status to report if image backup has failed.
 * @param update_start The status to report when the image has started update.
 * @param update_fail The status to report if the image update failed.
 * @param img_good Output indicating of the destination region contains a good image at the end of
 * this process.  It does not mean the new image is in the region, just that there is a good one,
 * such as when a backup image is restored in error handling.
 *
 * @return 0 if the new firmware image was successfully written or an error code.
 */
static int firmware_update_write_image (struct firmware_update *updater,
	struct firmware_update_notification *callback, struct flash *dest, uint32_t dest_addr,
	struct flash *backup, uint32_t backup_addr, size_t update_len,
	enum firmware_update_status backup_start, enum firmware_update_status backup_fail,
	enum firmware_update_status update_start, enum firmware_update_status update_fail,
	bool *img_good)
{
	int backup_len = 0;
	uint32_t page;
	int status;

	*img_good = true;
	if (backup) {
		/* Backup the current image. */
		firmware_update_status_change (callback, backup_start);
		status = updater->fw->load (updater->fw, dest, dest_addr + updater->img_offset);
		if (status != 0) {
			firmware_update_status_change (callback, backup_fail);
			return status;
		}

		backup_len = updater->fw->get_image_size (updater->fw);
		if (ROT_IS_ERROR (backup_len)) {
			firmware_update_status_change (callback, backup_fail);
			return backup_len;
		}

		status = flash_copy_ext_and_verify (backup, backup_addr + updater->img_offset, dest,
			dest_addr + updater->img_offset, backup_len);
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

	*img_good = false;
	status = flash_erase_region_and_verify (dest, dest_addr + updater->img_offset, update_len);
	if (status != 0) {
		firmware_update_status_change (callback, update_fail);
		return status;
	}

	status = firmware_update_program_bootable (updater, dest, dest_addr + updater->img_offset,
		updater->flash->staging_flash, updater->flash->staging_addr + updater->img_offset,
		update_len, page);
	if (status == 0) {
		status = firmware_update_finalize_image (updater, dest, dest_addr);
	}

	if (status != 0) {
		if (backup) {
			/* Try to restore the image that was backed up. */
			if (flash_erase_region_and_verify (dest, dest_addr + updater->img_offset,
				backup_len) == 0) {
				if (firmware_update_program_bootable (updater, dest,
					dest_addr + updater->img_offset, backup, backup_addr + updater->img_offset,
					backup_len, page) == 0) {
					if (firmware_update_finalize_image (updater, dest, dest_addr) == 0) {
						*img_good = true;
					}
				}
			}
		}

		firmware_update_status_change (callback, update_fail);
		return status;
	}

	*img_good = true;
	return 0;
}

/**
 * Run the firmware update process.  The firmware update will take the following steps:
 * 		- Validate the data store in the staging flash region to ensure a good image.
 * 		- Save the application state that should be restored after the update.
 * 		- Copy the image in staging flash to active flash.
 * 		- Copy the image in staging flash to recovery flash, if the recovery certificate has been
 * 			revoked.
 * 		- Update certificate revocation information in the device.
 *
 * @param updater The updater that should run.
 * @param callback A set of notification handlers to use during the update process.  This can be
 * null if no notifications are necessary.  Also, individual callbacks that are not desired can be
 * left null.
 *
 * @return 0 if the update completed successfully or an error code.
 */
int firmware_update_run_update (struct firmware_update *updater,
	struct firmware_update_notification *callback)
{
	int new_len;
	struct key_manifest *manifest;
	struct firmware_header *header = NULL;
	bool recovery_updated = false;
	bool img_good;
	int cert_revoked;
	int new_revision;
	int allow_update;
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_START_FAILURE);
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	/* Verify image in staging flash. */
	firmware_update_status_change (callback, UPDATE_STATUS_VERIFYING_IMAGE);

	if (flash_updater_get_remaining_bytes (&updater->update_mgr) > 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_INCOMPLETE_IMAGE);
		return FIRMWARE_UPDATE_INCOMPLETE_IMAGE;
	}

	status = updater->fw->load (updater->fw, updater->flash->staging_flash,
		updater->flash->staging_addr + updater->img_offset);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);
		return status;
	}

	status = updater->fw->verify (updater->fw, updater->hash, updater->rsa);
	if (status != 0) {
		if ((status == RSA_ENGINE_BAD_SIGNATURE) || (status == FIRMWARE_IMAGE_MANIFEST_REVOKED)) {
			firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);
		}
		else {
			firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);
		}
		return status;
	}

	header = updater->fw->get_firmware_header (updater->fw);
	if (header == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);
		return FIRMWARE_UPDATE_NO_FIRMWARE_HEADER;
	}

	status = firmware_header_get_recovery_revision (header, &new_revision);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);
		return status;
	}

	if (new_revision < updater->min_rev) {
		firmware_update_status_change (callback, UPDATE_STATUS_INVALID_IMAGE);
		return FIRMWARE_UPDATE_REJECTED_ROLLBACK;
	}

	new_len = updater->fw->get_image_size (updater->fw);
	if (ROT_IS_ERROR (new_len)) {
		firmware_update_status_change (callback, UPDATE_STATUS_VERIFY_FAILURE);
		return new_len;
	}

	/* Notify the system of an update and see if it should be allowed. */
	allow_update = 0;
	observable_notify_observers_with_ptr (&updater->observable,
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
	if (updater->flash->recovery_flash && updater->recovery_bad) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_RECOVERY_UPDATE, 0, 0);
		debug_log_flush ();

		status = firmware_update_write_image (updater, callback, updater->flash->recovery_flash,
			updater->flash->recovery_addr, NULL, 0, new_len, UPDATE_STATUS_BACKUP_RECOVERY,
			UPDATE_STATUS_BACKUP_REC_FAIL, UPDATE_STATUS_UPDATE_RECOVERY,
			UPDATE_STATUS_UPDATE_REC_FAIL, &img_good);
		if (status != 0) {
			return status;
		}

		updater->recovery_bad = !img_good;
		recovery_updated = true;
	}

	/* Update the active image from staging flash. */
	status = firmware_update_write_image (updater, callback, updater->flash->active_flash,
		updater->flash->active_addr, updater->flash->backup_flash, updater->flash->backup_addr,
		new_len, UPDATE_STATUS_BACKUP_ACTIVE, UPDATE_STATUS_BACKUP_FAILED,
		UPDATE_STATUS_UPDATING_IMAGE, UPDATE_STATUS_UPDATE_FAILED, &img_good);
	if (status != 0) {
		return status;
	}

	/* Check for certificate revocation. */
	firmware_update_status_change (callback, UPDATE_STATUS_CHECK_REVOCATION);
	status = updater->fw->load (updater->fw, updater->flash->active_flash,
		updater->flash->active_addr + updater->img_offset);
	if (status != 0) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);
		return status;
	}

	manifest = updater->fw->get_key_manifest (updater->fw);
	if (manifest == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);
		return FIRMWARE_UPDATE_NO_KEY_MANIFEST;
	}

	cert_revoked = manifest->revokes_old_manifest (manifest);
	if (ROT_IS_ERROR (cert_revoked)) {
		firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CHK_FAIL);
		return cert_revoked;
	}

	/* Check if recovery update is necessary. */
	firmware_update_status_change (callback, UPDATE_STATUS_CHECK_RECOVERY);
	if (cert_revoked || (updater->recovery_rev != new_revision)) {
		if (updater->flash->recovery_flash && !recovery_updated) {
			struct flash *backup;
			uint32_t backup_addr;

			if (updater->flash->rec_backup_flash) {
				backup = updater->flash->rec_backup_flash;
				backup_addr = updater->flash->rec_backup_addr;
			}
			else {
				backup = updater->flash->backup_flash;
				backup_addr = updater->flash->backup_addr;
			}

			/* Update the recovery image from staging flash. */
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_UPDATE, 0, 0);
			debug_log_flush ();

			status = firmware_update_write_image (updater, callback, updater->flash->recovery_flash,
				updater->flash->recovery_addr, backup, backup_addr, new_len,
				UPDATE_STATUS_BACKUP_RECOVERY, UPDATE_STATUS_BACKUP_REC_FAIL,
				UPDATE_STATUS_UPDATE_RECOVERY, UPDATE_STATUS_UPDATE_REC_FAIL, &img_good);

			updater->recovery_bad = !img_good;
			if (status != 0) {
				return status;
			}
		}

		updater->recovery_rev = new_revision;

		if (cert_revoked) {
			/* Revoke the old certificate. */
			firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_CERT);
			status = manifest->update_revocation (manifest);
			if (status != 0) {
				firmware_update_status_change (callback, UPDATE_STATUS_REVOKE_FAILED);
				return status;
			}
		}
	}

	/* Update completed successfully. */
	return 0;
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
int firmware_update_prepare_staging (struct firmware_update *updater,
	struct firmware_update_notification *callback, size_t size)
{
	int status;

	if (updater == NULL) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP_FAIL);
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	firmware_update_status_change (callback, UPDATE_STATUS_STAGING_PREP);

	status = flash_updater_prepare_for_update (&updater->update_mgr, size);
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
int firmware_update_write_to_staging (struct firmware_update *updater,
	struct firmware_update_notification *callback, uint8_t *buf, size_t buf_len)
{
	int status;

	if ((updater == NULL) || (buf == NULL)) {
		firmware_update_status_change (callback, UPDATE_STATUS_STAGING_WRITE_FAIL);
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	firmware_update_status_change (callback, UPDATE_STATUS_STAGING_WRITE);

	status = flash_updater_write_update_data (&updater->update_mgr, buf, buf_len);
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
 * have been received than expected.
 */
int firmware_update_get_update_remaining (struct firmware_update *updater)
{
	return flash_updater_get_remaining_bytes (&updater->update_mgr);
}
