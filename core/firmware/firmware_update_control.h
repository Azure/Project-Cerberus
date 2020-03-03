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
	 *
	 * @return 0 if the update was successfully started or an error code.
	 */
	int (*start_update) (struct firmware_update_control *update);

	/**
	 * Get the status of the last firmware update to run.
	 *
	 * @param update The update instance to query.
	 *
	 * @return The firmware update status.  The lower 8 bits will be the update status as per
	 * enum firmware_update_status.  The rest of the bits will be the return code from the update
	 * process.
	 */
	int (*get_status) (struct firmware_update_control *update);

	/**
	 * Get the remaining image length to be received.
	 *
	 * @param update The update instance to query.
	 *
	 * @return The remaining number of bytes.
	 */
	int32_t (*get_remaining_len) (struct firmware_update_control *update);

	/**
	 * Prepare staging area for incoming update.
	 *
	 * @param update The update instance to query.
	 * @param size Size of incoming update.
	 *
 	 * @return Preparation status, 0 if success or an error code.
	 */
	int (*prepare_staging) (struct firmware_update_control *update, size_t size);

	/**
	 * Write to staging area update data.
	 *
	 * @param update The update instance to query.
	 * @param buf Buffer with update data.
	 * @param buf_len Buffer length.
	 *
 	 * @return Write status, 0 if success or an error code.
	 */
	int (*write_staging) (struct firmware_update_control *update, uint8_t *buf, size_t buf_len);
};


#endif /* FIRMWARE_UPDATE_CONTROL_H_ */
