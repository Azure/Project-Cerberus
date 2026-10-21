// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_INTERFACE_H_
#define IMPACTFUL_UPDATE_INTERFACE_H_

#include <stdint.h>
#include "status/rot_status.h"


/**
 * Interface for managing impactful firmware updates.  The update itself will still be executed by
 * the firmware updater.  This interface provides details about the update to properly manage
 * updates that will be impactful.
 *
 * A typical firmware update is intended to be impactless, meaning the device will reset itself and
 * will not adversely impact system functionality.  An impactful update requires a deeper reset than
 * can be provided by the device (such as an AC cycle) or would otherwise impact functionality of
 * the system.
 */
struct impactful_update_interface {
	/**
	 * Determine if a firmware update would be impactful.
	 *
	 * @param impactful The impactful update context to query.
	 *
	 * @return 0 if the update is not impactful or an error code.
	 */
	int (*is_update_not_impactful) (const struct impactful_update_interface *impactful);

	/**
	 * Determine if an impactful firmware update is allowed to be accepted by the device.
	 *
	 * This is a combined check against whether the update is impactful and if impactful updates
	 * have been authorized.  Updates are only allowed if the update would not be impactful or if
	 * impactful updates have been properly authorized.
	 *
	 * @param impactful The impactful update context to query.
	 *
	 * @return 0 if the update is allowed or an error code.
	 */
	int (*is_update_allowed) (const struct impactful_update_interface *impactful);

	/**
	 * Authorize the device to accept an impactful firmware update.  This authorization cannot
	 * override any impactful checks that block update acceptance, but no failure will be reported
	 * until a blocked update is attempted.
	 *
	 * @param impactful The impactful update context to update.
	 * @param allowed_time_ms The amount of time the impactful authorization will remain valid, in
	 * milliseconds.  If this is 0, the authorization will not expire.
	 *
	 * @return 0 if impactful updates have been authorized or an error code.
	 */
	int (*authorize_update) (const struct impactful_update_interface *impactful,
		uint32_t allowed_time_ms);

	/**
	 * Remove authorization for impactful updates.  This can be called whether impactful updates are
	 * currently authorized or not.
	 *
	 * @param impactful The impactful update context to update.
	 *
	 * @return 0 if impactful update authorization has been reset or an error code.
	 */
	int (*reset_authorization) (const struct impactful_update_interface *impactful);
};


#define	IMPACTFUL_UPDATE_ERROR(code)		ROT_ERROR (ROT_MODULE_IMPACTFUL_UPDATE, code)

/**
 * Error codes that can be generated when handling an impactful firmware update.
 */
enum {
	IMPACTFUL_UPDATE_INVALID_ARGUMENT = IMPACTFUL_UPDATE_ERROR (0x00),			/**< Input parameter is null or not valid. */
	IMPACTFUL_UPDATE_NO_MEMORY = IMPACTFUL_UPDATE_ERROR (0x01),					/**< Memory allocation failed. */
	IMPACTFUL_UPDATE_IS_NOT_IMPACTFUL_FAILED = IMPACTFUL_UPDATE_ERROR (0x02),	/**< Failed to determine if an update is impactful. */
	IMPACTFUL_UPDATE_IS_ALLOWED_FAILED = IMPACTFUL_UPDATE_ERROR (0x03),			/**< Failed to determine if an update is blocked. */
	IMPACTFUL_UPDATE_AUTHORIZE_FAILED = IMPACTFUL_UPDATE_ERROR (0x04),			/**< Failed to authorize impactful updates. */
	IMPACTFUL_UPDATE_RESET_AUTH_FAILED = IMPACTFUL_UPDATE_ERROR (0x05),			/**< Failed to reset impactful update authorization. */
	IMPACTFUL_UPDATE_NOT_ALLOWED = IMPACTFUL_UPDATE_ERROR (0x06),				/**< The update is not allowed for use. */
	IMPACTFUL_UPDATE_BLOCKED = IMPACTFUL_UPDATE_ERROR (0x07),					/**< The update is not allowed and cannot be authorized. */
};


#endif	/* IMPACTFUL_UPDATE_INTERFACE_H_ */
