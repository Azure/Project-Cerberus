// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_H_
#define FIRMWARE_UPDATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "app_context.h"
#include "firmware_image.h"
#include "firmware_update_observer.h"
#include "common/observable.h"
#include "crypto/hash.h"
#include "flash/flash.h"
#include "flash/flash_updater.h"
#include "status/rot_status.h"
#include "system/security_manager.h"


/**
 * The flash addresses and devices to use for different firmware regions.
 */
struct firmware_flash_map {
	const struct flash *active_flash;		/**< The flash device that contains the active region. */
	uint32_t active_addr;					/**< The base address for the active flash region. */
	size_t active_size;						/**< The size of the active flash region. */
	const struct flash *backup_flash;		/**< The flash device that contains the backup region. */
	uint32_t backup_addr;					/**< The base address for the backup flash region. */
	size_t backup_size;						/**< The size of the backup flash region. */
	const struct flash *staging_flash;		/**< The flash device that contains the staging region. */
	uint32_t staging_addr;					/**< The base address for the staging flash region. */
	size_t staging_size;					/**< The size of the staging flash region. */
	const struct flash *recovery_flash;		/**< The flash device that contains the recovery region. */
	uint32_t recovery_addr;					/**< The base address for the recovery flash region. */
	size_t recovery_size;					/**< The size of the recovery flash region. */
	const struct flash *rec_backup_flash;	/**< The flash device for the recovery backup region. */
	uint32_t rec_backup_addr;				/**< The base address for the recovery backup region. */
	size_t rec_backup_size;					/**< The size of the recovery backup flash region. */
};

/**
 * The valid update status values.
 */
enum firmware_update_status {
	UPDATE_STATUS_SUCCESS = 0,			/**< Successful update. */
	UPDATE_STATUS_STARTING,				/**< The update process is starting. */
	UPDATE_STATUS_START_FAILURE,		/**< Failed to start the update process. */
	UPDATE_STATUS_VERIFYING_IMAGE,		/**< Verifying the staging image. */
	UPDATE_STATUS_INCOMPLETE_IMAGE,		/**< Failed to receive the entire update image. */
	UPDATE_STATUS_VERIFY_FAILURE,		/**< A failure while verifying the staging flash. */
	UPDATE_STATUS_INVALID_IMAGE,		/**< The staging image is not valid. */
	UPDATE_STATUS_BACKUP_ACTIVE,		/**< Backing up the current image. */
	UPDATE_STATUS_BACKUP_FAILED,		/**< The current image failed to be backed up. */
	UPDATE_STATUS_SAVING_STATE,			/**< The current application state is being saved. */
	UPDATE_STATUS_STATE_SAVE_FAIL,		/**< The application state was not saved. */
	UPDATE_STATUS_UPDATING_IMAGE,		/**< The active image is being updated from the staging flash. */
	UPDATE_STATUS_UPDATE_FAILED,		/**< Failed to update the active image. */
	UPDATE_STATUS_CHECK_REVOCATION,		/**< Check the new image manifest for revocation of older ones. */
	UPDATE_STATUS_REVOKE_CHK_FAIL,		/**< Error while checking for image revocation. */
	UPDATE_STATUS_CHECK_RECOVERY,		/**< Check the recovery image to see if update is required. */
	UPDATE_STATUS_RECOVERY_CHK_FAIL,	/**< Error while checking for recovery updates. */
	UPDATE_STATUS_BACKUP_RECOVERY,		/**< The recovery image is being backed up. */
	UPDATE_STATUS_BACKUP_REC_FAIL,		/**< The recovery image failed to be backed up. */
	UPDATE_STATUS_UPDATE_RECOVERY,		/**< The recovery image is being updated from the staging flash. */
	UPDATE_STATUS_UPDATE_REC_FAIL,		/**< Failed to update the recovery image. */
	UPDATE_STATUS_REVOKE_MANIFEST,		/**< The manifest revocation state is being updated. */
	UPDATE_STATUS_REVOKE_FAILED,		/**< The revocation state failed updating. */
	UPDATE_STATUS_NONE_STARTED,			/**< No update has been attempted since the last reboot. */
	UPDATE_STATUS_STAGING_PREP_FAIL,	/**< Failed to prepare staging area for update. */
	UPDATE_STATUS_STAGING_PREP,			/**< Preparing staging area for update. */
	UPDATE_STATUS_STAGING_WRITE_FAIL,	/**< Failed to program staging area with update packet. */
	UPDATE_STATUS_STAGING_WRITE,		/**< Programming staging area with update packet. */
	UPDATE_STATUS_REQUEST_BLOCKED,		/**< A request has been made before the previous one finished. */
	UPDATE_STATUS_TASK_NOT_RUNNING,		/**< The task servicing update request is not running. */
	UPDATE_STATUS_UNKNOWN,				/**< The update status cannot be determined. */
	UPDATE_STATUS_SYSTEM_PREREQ_FAIL,	/**< The system state does not allow for firmware updates. */
};

struct firmware_update;

/**
 * Internal hooks to handle deviations from the standard update flow.  Unneeded hooks can be null.
 */
struct firmware_update_hooks {
	/**
	 * Finalize the firmware image written to flash.  This will be called after the entire image in
	 * staging flash has been written to active or recovery flash.
	 *
	 * @param updater The firmware updater that has written the image.
	 * @param flash The flash device that was written with a new image.
	 * @param address The base address of the firmware region that was written.  This may not be the
	 * same as the start address of the firmware image, depending on whether an image offset was
	 * used.  If there is an image offset, the updater will ensure the flash is erased starting from
	 * the base address.
	 *
	 * @return 0 if the image was successfully finalized or an error code.
	 */
	int (*finalize_image) (const struct firmware_update *updater, const struct flash *flash,
		uint32_t address);

	/**
	 * Run additional verification on a boot image stored on flash.  This will be called after
	 * running typical verification on a firmware image.
	 *
	 * This verification will not be called for an image in staging flash.
	 *
	 * @param updater The firmware updater to run the verification.
	 * @param flash The flash device that contains the boot image to verify.
	 * @param address The base address of the boot image.
	 *
	 * @return 0 if the image is valid or an error code.  If the boot image is not valid,
	 * FIRMWARE_UPDATE_INVALID_BOOT_IMAGE will be returned.
	 */
	int (*verify_boot_image) (const struct firmware_update *updater, const struct flash *flash,
		uint32_t address);
};

/**
 * Variable context for a firmware updater.
 */
struct firmware_update_state {
	struct flash_updater update_mgr;	/**< Update manager for writing data to flash. */
	struct observable observable;		/**< Observer manager for the updater. */
	bool recovery_bad;					/**< Indication if the recovery image on flash is bad. */
	int recovery_rev;					/**< Revision ID of the current recovery image. */
	int min_rev;						/**< Minimum revision ID allowed for update. */
	int img_offset;						/**< Offset to apply to FW image regions. */
};

/**
 * The meta-data and other dependencies necessary to run firmware update operations.
 */
struct firmware_update {
	struct firmware_update_hooks internal;		/**< Internal interface to customize the update process. */
	struct firmware_update_state *state;		/**< Variable context for the firmware updater. */
	const struct firmware_flash_map *flash;		/**< The flash address mapping to use for the update. */
	const struct firmware_image *fw;			/**< The platform driver for handling firmware images. */
	const struct security_manager *security;	/**< The manager for the current security policy. */
	struct hash_engine *hash;					/**< The hash engine to use during update. */
	const struct app_context *context;			/**< The platform application context API. */
	bool no_fw_header;							/**< Indication that a firmware header is not required. */
};

/**
 * Callbacks that can be implemented to get notified of information from the firmware update.
 */
struct firmware_update_notification {
	/**
	 * Notification that the status of the active firmware update has changed.
	 *
	 * @param context The context of the notification handler.
	 * @param status The new status of the active firmware update.
	 */
	void (*status_change) (const struct firmware_update_notification *context,
		enum firmware_update_status status);
};


int firmware_update_init (struct firmware_update *updater, struct firmware_update_state *state,
	const struct firmware_flash_map *flash, const struct app_context *context,
	const struct firmware_image *fw, const struct security_manager *security,
	struct hash_engine *hash, int allowed_revision);
int firmware_update_init_no_firmware_header (struct firmware_update *updater,
	struct firmware_update_state *state, const struct firmware_flash_map *flash,
	const struct app_context *context, const struct firmware_image *fw,
	const struct security_manager *security, struct hash_engine *hash, int allowed_revision);
int firmware_update_init_state (const struct firmware_update *updater, int allowed_revision);
void firmware_update_release (const struct firmware_update *updater);

void firmware_update_set_image_offset (const struct firmware_update *updater, int offset);

void firmware_update_set_recovery_revision (const struct firmware_update *updater, int revision);
void firmware_update_set_recovery_good (const struct firmware_update *updater, bool img_good);
void firmware_update_validate_recovery_image (const struct firmware_update *updater);
int firmware_update_is_recovery_good (const struct firmware_update *updater);

int firmware_update_restore_recovery_image (const struct firmware_update *updater);
int firmware_update_restore_active_image (const struct firmware_update *updater);
int firmware_update_recovery_matches_active_image (const struct firmware_update *updater);

int firmware_update_add_observer (const struct firmware_update *updater,
	const struct firmware_update_observer *observer);
int firmware_update_remove_observer (const struct firmware_update *updater,
	const struct firmware_update_observer *observer);

int firmware_update_run_update (const struct firmware_update *updater,
	const struct firmware_update_notification *callback);
int firmware_update_run_update_no_revocation (const struct firmware_update *updater,
	const struct firmware_update_notification *callback);
int firmware_update_run_revocation (const struct firmware_update *updater,
	const struct firmware_update_notification *callback);

int firmware_update_prepare_staging (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, size_t size);
int firmware_update_write_to_staging (const struct firmware_update *updater,
	const struct firmware_update_notification *callback, uint8_t *buf, size_t buf_len);
int firmware_update_get_update_remaining (const struct firmware_update *updater);


#define	FIRMWARE_UPDATE_ERROR(code)		ROT_ERROR (ROT_MODULE_FIRMWARE_UPDATE, code)

/**
 * Error codes that can be generated by the firmware updater.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	FIRMWARE_UPDATE_INVALID_ARGUMENT = FIRMWARE_UPDATE_ERROR (0x00),	/**< Input parameter is null or not valid. */
	FIRMWARE_UPDATE_NO_MEMORY = FIRMWARE_UPDATE_ERROR (0x01),			/**< Memory allocation failed. */
//	FIRMWARE_UPDATE_CONTEXT_SAVE_FAILED = FIRMWARE_UPDATE_ERROR (0x02),	/**< The running context has not been saved. */
	FIRMWARE_UPDATE_FINALIZE_IMG_FAILED = FIRMWARE_UPDATE_ERROR (0x03),	/**< A generic error while executing the finalize hook. */
	FIRMWARE_UPDATE_VERIFY_BOOT_FAILED = FIRMWARE_UPDATE_ERROR (0x04),	/**< An error not related to image validation caused verification to fail. */
	FIRMWARE_UPDATE_INVALID_FLASH_MAP = FIRMWARE_UPDATE_ERROR (0x05),	/**< The flash map provided to the updater is not valid. */
	FIRMWARE_UPDATE_INCOMPLETE_IMAGE = FIRMWARE_UPDATE_ERROR (0x06),	/**< The staging flash has not been programmed with all expected data. */
	FIRMWARE_UPDATE_NO_KEY_MANIFEST = FIRMWARE_UPDATE_ERROR (0x07),		/**< Could not retrieve the key manifest for the new image. */
//	FIRMWARE_UPDATE_IMG_TOO_LARGE = FIRMWARE_UPDATE_ERROR (0x08),		/**< The new image is too big for the staging flash region. */
//	FIRMWARE_UPDATE_NO_SPACE = FIRMWARE_UPDATE_ERROR (0x09),			/**< Not enough space remaining in staging flash for more data. */
//	FIRMWARE_UPDATE_INCOMPLETE_WRITE = FIRMWARE_UPDATE_ERROR (0x0a),	/**< Update payload was only partially written to flash. */
	FIRMWARE_UPDATE_NO_TASK = FIRMWARE_UPDATE_ERROR (0x0b),				/**< No update task is running .*/
	FIRMWARE_UPDATE_TASK_BUSY = FIRMWARE_UPDATE_ERROR (0x0c),			/**< The update task is busy performing an operation. */
	FIRMWARE_UPDATE_NO_FIRMWARE_HEADER = FIRMWARE_UPDATE_ERROR (0x0d),	/**< Could not retrieve the firmware header for the new image. */
	FIRMWARE_UPDATE_REJECTED_ROLLBACK = FIRMWARE_UPDATE_ERROR (0x0e),	/**< The new image revision ID is a disallowed version. */
	FIRMWARE_UPDATE_NO_RECOVERY_IMAGE = FIRMWARE_UPDATE_ERROR (0x0f),	/**< There is no recovery image available for the operation. */
	FIRMWARE_UPDATE_RESTORE_NOT_NEEDED = FIRMWARE_UPDATE_ERROR (0x10),	/**< An image restore operation was not necessary. */
	FIRMWARE_UPDATE_INVALID_BOOT_IMAGE = FIRMWARE_UPDATE_ERROR (0x11),	/**< The boot image is not valid based on additional verification. */
	FIRMWARE_UPDATE_TOO_MUCH_DATA = FIRMWARE_UPDATE_ERROR (0x12),		/**< Too much data was sent in a single request. */
};


#endif	/* FIRMWARE_UPDATE_H_ */
