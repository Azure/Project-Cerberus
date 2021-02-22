// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_MANAGER_H_
#define RECOVERY_IMAGE_MANAGER_H_

#include "platform.h"
#include "recovery_image.h"
#include "common/observable.h"
#include "common/signature_verification.h"
#include "recovery_image_observer.h"
#include "flash/flash.h"
#include "flash/flash_updater.h"
#include "crypto/hash.h"
#include "host_fw/host_state_manager.h"


/**
 * Container of information for a recovery image region on flash.
 */
struct recovery_image_manager_flash_region {
	struct recovery_image *image;			/**< The recovery image instance on flash. */
	bool is_valid;							/**< Flag indicating if the flash region has a valid recovery image. */
	int ref_count;							/**< The number of active references to the recovery image region. */
	struct flash_updater updater;			/**< Update manager for writing data to flash. */
};

/**
 * API for managing a recovery image.
 */
struct recovery_image_manager {

	/**
	 * Verify and activate the recovery image that has been written to flash. Successful
	 * verification is a requirement for activation.
	 *
	 * @param manager The recovery image manager to update.
	 *
	 * @return 0 if the recovery image was successfully activated or an error code.
	 */
	int (*activate_recovery_image) (struct recovery_image_manager *manager);

	/**
	 * Clear the recovery image region in order to accept new recovery image data. This operation
	 * effectively discards any active recovery image in the region.
	 *
	 * @param manager The recovery image manager for the region to clear.
	 * @param size Size of the incoming recovery image.
	 *
	 * @return 0 if the pending recovery image region was successfully cleared or an error code.
	 */
	int (*clear_recovery_image_region) (struct recovery_image_manager *manager, size_t size);

	/**
	 * Write data to the recovery image region. This data must be written sequentially.
	 *
	 * @param manager The recovery image manager for the pending region to write to.
	 * @param data The data that should be written.
	 * @param length The length of the data to write.
	 *
	 * @return 0 if the data was successfully written or an error code.
	 */
	int (*write_recovery_image_data) (struct recovery_image_manager *manager, const uint8_t *data,
		size_t length);

	/**
	 * Get the active recovery image for the protected flash.  The recovery image instance must be
	 * released with the manager.
	 *
	 * @param manager The recovery image manager to query.
	 *
	 * @return The active recovery image or null if there is no active recovery image.
	 */
	struct recovery_image* (*get_active_recovery_image) (struct recovery_image_manager *manager);

	/**
	 * Release a recovery image instance retrieved from the manager.  Recovery image instances must
	 * only be released by the manager that allocated them.
	 *
	 * @param manager The recovery image manager that allocated the recovery image instance.
	 * @param image The recovery image to release.
	 */
	void (*free_recovery_image) (struct recovery_image_manager *manager,
		struct recovery_image *image);

	/**
	 * Get the flash update manager being used to update a recovery image. The flash update manager
	 * will be a valid instance during a recovery image update operation and will be NULL after
	 * the update operation is complete.
	 *
	 * @param manager The recovery image manager to query.
	 *
	 * @return The flash update manager or null if there is no manager.
	 */
	struct flash_updater* (*get_flash_update_manager) (struct recovery_image_manager *manager);

	/**
	 * Erase all recovery image regions including active and inactive regions.
	 *
	 * @param manager The recovery image manager for the regions to erase.
	 *
	 * @return 0 if all recovery image regions were successfully erased or an error code.
	 */
	int (*erase_all_recovery_regions) (struct recovery_image_manager *manager);

	/**
	 * Internal function to get the requested recovery image region.
	 */
	struct {
		/**
		 * Get the requested recovery image region.
		 *
		 * @param manager The recovery image manager instance to query.
		 * @param active Flag to indicate to retrieve the active or inactive region.
		 *
		 * @return The requested recovery image region.
		 */
		struct recovery_image_manager_flash_region* (*get_region) (
			struct recovery_image_manager *manager, bool active);
	} internal;

	struct observable observable;						/**< The manager for recovery image observers. */
	struct recovery_image_manager_flash_region region1;	/**< The first flash region for a recovery image. */
	struct recovery_image_manager_flash_region region2;	/**< The second flash region for a recovery image. */
	struct hash_engine *hash;							/**< The hash engine for recovery image validation. */
	struct signature_verification *verification;		/**< Verification module for verifying recovery
															 image signatures. */
	struct pfm_manager *pfm;							/**< The PFM manager for recovery image verification. */
	platform_mutex lock;								/**< Synchronization for recovery image manager state. */
	int port;											/**< Port identifier for the manager. */
	struct host_state_manager *state;					/**< State manager interface. */
	struct flash_updater *updating;                 	/**< The update manager being used to write
															 new recovery image data. */
};


int recovery_image_manager_init (struct recovery_image_manager *manager,
	struct recovery_image *image, struct hash_engine *hash,
	struct signature_verification *verification, struct pfm_manager *pfm, size_t max_size);
int recovery_image_manager_init_two_region (struct recovery_image_manager *manager,
	struct recovery_image *image1, struct recovery_image *image2, struct host_state_manager *state,
	struct hash_engine *hash, struct signature_verification *verification, struct pfm_manager *pfm,
	size_t max_size);
void recovery_image_manager_release (struct recovery_image_manager *manager);

int recovery_image_manager_add_observer (struct recovery_image_manager *manager,
	struct recovery_image_observer *observer);
int recovery_image_manager_remove_observer (struct recovery_image_manager *manager,
	struct recovery_image_observer *observer);

void recovery_image_manager_set_port (struct recovery_image_manager *manager, int port);
int recovery_image_manager_get_port (struct recovery_image_manager *manager);

int recovery_image_manager_get_measured_data (struct recovery_image_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len);


#define	RECOVERY_IMAGE_MANAGER_ERROR(code)		ROT_ERROR (ROT_MODULE_RECOVERY_IMAGE_MANAGER, code)

/**
 * Error codes that can be generated by a recovery image manager.
 */
enum {
	RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT = RECOVERY_IMAGE_MANAGER_ERROR (0x00),	/**< Input parameter is null or not valid. */
	RECOVERY_IMAGE_MANAGER_NO_MEMORY = RECOVERY_IMAGE_MANAGER_ERROR (0x01),			/**< Memory allocation failed. */
	RECOVERY_IMAGE_MANAGER_IMAGE_IN_USE = RECOVERY_IMAGE_MANAGER_ERROR (0x02),		/**< The recovery image is actively being used. */
	RECOVERY_IMAGE_MANAGER_NOT_CLEARED = RECOVERY_IMAGE_MANAGER_ERROR (0x03),		/**< The recovery image region was not cleared before write. */
	RECOVERY_IMAGE_MANAGER_INCOMPLETE_UPDATE = RECOVERY_IMAGE_MANAGER_ERROR (0x04),	/**< The flash has not been programmed with all the expected data. */
	RECOVERY_IMAGE_MANAGER_NONE_PENDING = RECOVERY_IMAGE_MANAGER_ERROR (0x05),		/**< There is no recovery image pending for the operation. */
	RECOVERY_IMAGE_MANAGER_TASK_BUSY = RECOVERY_IMAGE_MANAGER_ERROR (0x06),			/**< The command task is busy performing an operation. */
	RECOVERY_IMAGE_MANAGER_NO_TASK = RECOVERY_IMAGE_MANAGER_ERROR (0x07),			/**< No manager command task is running. */
	RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP = RECOVERY_IMAGE_MANAGER_ERROR (0x08),	/**< The requested operation is not supported by the manager. */
	RECOVERY_IMAGE_MANAGER_NO_IMAGE = RECOVERY_IMAGE_MANAGER_ERROR (0x09),			/**< No recovery image is available. */
};


#endif /* RECOVERY_IMAGE_MANAGER_H_ */

