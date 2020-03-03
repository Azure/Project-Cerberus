// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_CMD_INTERFACE_H_
#define RECOVERY_IMAGE_CMD_INTERFACE_H_

#include <stdint.h>


/**
 * Status codes for recovery image operations. MAKE SURE IN SYNC WITH tools\cerberus_utility\cerberus_utility_commands.h!!
 */
enum recovery_image_cmd_status {
	RECOVERY_IMAGE_CMD_STATUS_SUCCESS = 0,				/**< Successful operation. */
	RECOVERY_IMAGE_CMD_STATUS_STARTING,					/**< The recovery image operation is starting. */
	RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED,			/**< A request has been made before the previous one finished. */
	RECOVERY_IMAGE_CMD_STATUS_PREPARE,					/**< The recovery image is being prepared for updating. */
	RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL,				/**< There was an error preparing the recovery image for updating. */
	RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA,				/**< New recovery image data is being stored. */
	RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL,				/**< There was an error storing the recovery image data. */
	RECOVERY_IMAGE_CMD_STATUS_ACTIVATING,				/**< Activation is being attempted for a new recovery image. */
	RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL,			/**< There was an error activating the new recovery image. */
	RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR,			/**< An unspecified, internal error occurred. */
	RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED,				/**< No recovery image operation has been started. */
	RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING,			/**< The task servicing recovery image operations is not running. */
	RECOVERY_IMAGE_CMD_STATUS_UNKNOWN,					/**< The recovery image update status could not be determined. */
};

/**
 * Make a status value suitable to be returned by get_status.
 *
 * @param status The status per recovery_image_cmd_status.
 * @param error The error code for the operation.
 */
#define	RECOVERY_IMAGE_CMD_STATUS(status, error)	(((error & 0xffffff) << 8) | status)


/**
 * Defines the API to handle commands for a recovery image.
 */
struct recovery_image_cmd_interface {
	/**
	 * Prepare system for receiving new recovery image data. This will return immediately,
	 * with the status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the recovery image instance to prepare for update.
	 * @param image_size Size of the incoming image. 
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*prepare_recovery_image) (struct recovery_image_cmd_interface *cmd, uint32_t image_size);

	/**
	 * Indicate that new recovery image data should be stored. This will return immediately, with the
	 * status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the recovery image to store.
	 * @param data The recovery image data to store.
	 * @param length The bytes of recovery image data to store.
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*update_recovery_image) (struct recovery_image_cmd_interface *cmd, const uint8_t *data,
		size_t length);

	/**
	 * Indicate that a complete recovery image has been received and should be activated. This will
	 * return immediately, with the status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the recovery image instance to activate.
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*activate_recovery_image) (struct recovery_image_cmd_interface *cmd);

	/**
	 * Get the status of the last image operation requested.
	 *
	 * @param cmd The command interface for the image to query.
	 *
	 * @return The image operation status. The lower 8 bits will be the operation status as per
	 * enum image_cmd_status. The remaining bits will be the return code from the image
	 * operation.
	 */
	int (*get_status) (struct recovery_image_cmd_interface *cmd);
};


#endif /* RECOVERY_IMAGE_CMD_INTERFACE_H_ */
