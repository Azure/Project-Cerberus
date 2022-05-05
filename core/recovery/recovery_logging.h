// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_LOGGING_H_
#define RECOVERY_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for a recovery processing.
 */
enum {
	RECOVERY_LOGGING_RECORD_MEASUREMENT_FAIL,		/**< Failed to record a recovery image measurement in PCR store. */
	RECOVERY_LOGGING_GET_MEASUREMENT_FAIL,			/**< Failed to get a recovery image measurement. */
	RECOVERY_LOGGING_ACTIVATED_EVENT_FAIL,			/**< Failed recovery image activation notification. */
	RECOVERY_LOGGING_RECORD_INVALID,				/**< Invalid call to force recovery image measurements. */
	RECOVERY_LOGGING_WRITE_FAIL,					/**< Failed to write recovery image data. */
	RECOVERY_LOGGING_VERIFY_FAIL,					/**< Failed to verify the new recovery image. */
	RECOVERY_LOGGING_NOTIFICATION_ERROR,			/**< Unknown task action specified. */
	RECOVERY_LOGGING_ACTIVATION_FLASH_ERROR,		/**< Critical failure during activation. */
	RECOVERY_LOGGING_ACTIVATION_FAIL,				/**< Failed to activate the recovery image. */
	RECOVERY_LOGGING_ERASE_FAIL,					/**< Failed to erase recovery image region. */
	RECOVERY_LOGGING_INVALIDATE_MEASUREMENT_FAIL,	/**< Failed to invalidate a recovery image measurement. */
	RECOVERY_LOGGING_OCP_READ_ERROR,				/**< Error processing an OCP read request. */
	RECOVERY_LOGGING_OCP_WRITE_ERROR,				/**< Error processing an OCP write request. */
	RECOVERY_LOGGING_OCP_PEC_ERROR,					/**< PEC error on a received request. */
	RECOVERY_LOGGING_OCP_WRITE_INCOMPLETE,			/**< An incomplete block write command was received. */
	RECOVERY_LOGGING_OCP_WRITE_OVERFLOW,			/**< More data than is allowed was sent. */
};


#endif /* RECOVERY_LOGGING_H_ */
