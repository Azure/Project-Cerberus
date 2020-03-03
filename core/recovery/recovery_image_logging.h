// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_LOGGING_H_
#define RECOVERY_IMAGE_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for a recovery image.
 */
enum {
	RECOVERY_IMAGE_LOGGING_RECORD_MEASUREMENT_FAIL,		/**< Failed to record a recovery image measurement in PCR store. */
	RECOVERY_IMAGE_LOGGING_GET_MEASUREMENT_FAIL,		/**< Failed to get a recovery image measurement. */
	RECOVERY_IMAGE_LOGGING_ACTIVATED_EVENT_FAIL,		/**< Failed recovery image activation notification. */
	RECOVERY_IMAGE_LOGGING_RECORD_INVALID,				/**< Invalid call to force recovery image measurements. */
	RECOVERY_IMAGE_LOGGING_WRITE_FAIL,					/**< Failed to write recovery image data. */
	RECOVERY_IMAGE_LOGGING_VERIFY_FAIL,					/**< Failed to verify the new recovery image. */
	RECOVERY_IMAGE_LOGGING_NOTIFICATION_ERROR,			/**< Unknown task action specified. */
	RECOVERY_IMAGE_LOGGING_ACTIVATION_FLASH_ERROR,		/**< Critical failure during activation. */
	RECOVERY_IMAGE_LOGGING_ACTIVATION_FAIL,				/**< Failed to activate the recovery image. */
	RECOVERY_IMAGE_LOGGING_ERASE_FAIL,					/**< Failed to erase recovery image region. */
	RECOVERY_IMAGE_LOGGING_INVALIDATE_MEASUREMENT_FAIL,	/**< Failed to invalidate a recovery image measurement. */
};


#endif /* RECOVERY_IMAGE_LOGGING_H_ */
