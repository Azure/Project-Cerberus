// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_CONTROL_H_
#define FIRMWARE_UPDATE_CONTROL_H_

#include "firmware_update.h"


/**
 * A platform-independent API for communicating with the firmware update process.
 */
struct firmware_update_control {
	/**
	 * Trigger the start of a firmware update process.  This will immediately return with update
	 * progress being reported separately.
	 *
	 * @param update The update instance to trigger.
	 * @param execute_on_completion Flag to indicate that the new firmware should automatically be
	 * executed upon successful completion of the update process.  If this is false, the new
	 * firmware will be stored in the boot flash, but the device will continue to run the current
	 * firmware.
	 *
	 * @return 0 if the update was successfully started or an error code.
	 */
	int (*start_update) (const struct firmware_update_control *update, bool execute_on_completion);

	/**
	 * Get the status of the last firmware update to run.
	 *
	 * @param update The update instance to query.
	 *
	 * @return The firmware update status.  The lower 8 bits will be the update status as per
	 * enum firmware_update_status.  The rest of the bits will be the return code from the update
	 * process.
	 */
	int (*get_status) (const struct firmware_update_control *update);

	/**
	 * Get the remaining image length to be received.
	 *
	 * @param update The update instance to query.
	 *
	 * @return The remaining number of bytes.
	 */
	int32_t (*get_remaining_len) (const struct firmware_update_control *update);

	/**
	 * Prepare the staging area for an incoming update.  This will immediately return with progress
	 * being reported separately.
	 *
	 * @param update The update instance to trigger.
	 * @param size Total size of the update image that will be sent.
	 *
	 * @return Preparation status, 0 if success or an error code.
	 */
	int (*prepare_staging) (const struct firmware_update_control *update, size_t size);

	/**
	 * Provide a digest for the incoming update data.  This digest will be used to verify the
	 * received data matched what was expected.  This should be called after preparing for an update
	 * but before receiving any update data.  This means the digest should be provided between calls
	 * to firmware_update_control.prepare_staging() and firmware_update_control.write_staging().
	 *
	 * @param update The update instance.
	 * @param hash_type Hash algorithm used to generate the image digest.
	 * @param digest Digest of the complete update image that will be transmitted.
	 * @param length Length of the image digest.
	 *
	 * @return 0 if the image digest was set successfully or an error code.
	 */
	int (*set_image_digest) (const struct firmware_update_control *update, enum hash_type hash_type,
		const uint8_t *digest, size_t length);

	/**
	 * Write update image data to the staging area.  This will immediately return with progress
	 * being reported separately.
	 *
	 * @param update The update instance to trigger.
	 * @param buf Buffer with the update image data to write.
	 * @param buf_len Length of the image data.
	 *
	 * @return Write status, 0 if success or an error code.
	 */
	int (*write_staging) (const struct firmware_update_control *update, uint8_t *buf,
		size_t buf_len);
};


#endif	/* FIRMWARE_UPDATE_CONTROL_H_ */
