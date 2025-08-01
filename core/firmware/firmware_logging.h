// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_LOGGING_H_
#define FIRMWARE_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for Cerberus firmware images.
 */
enum {
	FIRMWARE_LOGGING_RECOVERY_IMAGE,			/**< The state of the recovery image. */
	FIRMWARE_LOGGING_UPDATE_FAIL,				/**< Error updating the firmware image. */
	FIRMWARE_LOGGING_UPDATE_START,				/**< Start processing a received firmware image. */
	FIRMWARE_LOGGING_UPDATE_COMPLETE,			/**< Firmware update completed successfully. */
	FIRMWARE_LOGGING_ERASE_FAIL,				/**< Failed to erase firmware staging region. */
	FIRMWARE_LOGGING_WRITE_FAIL,				/**< Failed to write firmware image data. */
	FIRMWARE_LOGGING_RECOVERY_RESTORE_FAIL,		/**< Failed to restore a bad recovery image. */
	FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE,		/**< Done restoring a bad active image. */
	FIRMWARE_LOGGING_ACTIVE_RESTORE_START,		/**< Start to restore a bad active image. */
	FIRMWARE_LOGGING_RECOVERY_RESTORE_START,	/**< Start to restore a bad recovery image. */
	FIRMWARE_LOGGING_RECOVERY_UPDATE,			/**< Start to update a recovery image. */
	FIRMWARE_LOGGING_REVOCATION_UPDATE,			/**< Device anti-rollback state is being updated. */
	FIRMWARE_LOGGING_REVOCATION_FAIL,			/**< Error during revocation checks. */
	FIRMWARE_LOGGING_ALLOW_IMPACTFUL_UPDATE,	/**< Impactful updates have been authorized. */
	FIRMWARE_LOGGING_ALLOW_IMPACTFUL_FAIL,		/**< Failed to authorize impactful updates. */
	FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH,	/**< Detected an unauthorized impactful update. */
	FIRMWARE_LOGGING_IMPACTFUL_BLOCKED,			/**< Blocked an impactful update that cannot be authorized. */
	FIRMWARE_LOGGING_IMPACTFUL_UPDATE,			/**< Successfully applied an impactful update. */
	FIRMWARE_LOGGING_IMPACTFUL_RESET_AUTH_FAIL,	/**< Failed to reset impactful authorization after an update. */
	FIRMWARE_LOGGING_RECOVERY_COMPARE_FAIL,		/**< Failed to compare active and recovery images on flash. */
	FIRMWARE_LOGGING_RECOVERY_UPDATE_DONE,		/**< Done updating the recovery image. */
	FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL,	/**< Failed to prepare for a firmware update after authorization. */
};


#endif	/* FIRMWARE_LOGGING_H_ */
