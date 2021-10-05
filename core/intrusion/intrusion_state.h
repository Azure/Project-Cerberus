// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_STATE_H_
#define INTRUSION_STATE_H_

#include "status/rot_status.h"


/**
 * Manage the device's intrusion state. Intrusions are tracked as a means of improving
 * device security.
 */
struct intrusion_state {
	/**
	 * Set the intrusion state to "intrusion detected".
	 *
	 * @param intrusion The intrusion state instance being tracked.
	 *
	 * @return 0 if setting successful or an error code.
	 */
	int (*set) (struct intrusion_state *intrusion);

	/**
	 * Clear the intrusion state to "no intrusion".
	 *
	 * @param intrusion The intrusion state instance being tracked.
	 *
	 * @return 0 if clearing successful or an error code.
	 */
	int (*clear) (struct intrusion_state *intrusion);

	/**
	 * Check the intrusion state for the device.
	 *
	 * @param intrusion The intrusion state instance being tracked.
	 *
	 * @return 0 if no intrusion, 1 if intrusion detected, or an error code.  Some implementations
	 * may run state checking in the background and report updates through asynchronous
	 * notifications.  If this approach is taken, INTRUSION_STATE_CHECK_DEFERRED will be returned.
	 */
	int (*check) (struct intrusion_state *intrusion);
};


#define	INTRUSION_STATE_ERROR(code)		ROT_ERROR (ROT_MODULE_INTRUSION_STATE, code)

/**
 * Error codes for intrusion state information.
 */
enum {
	INTRUSION_STATE_INVALID_ARGUMENT = INTRUSION_STATE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	INTRUSION_STATE_NO_MEMORY = INTRUSION_STATE_ERROR (0x01),				/**< Memory allocation failed. */
	INTRUSION_STATE_SET_FAILED = INTRUSION_STATE_ERROR (0x02),				/**< Failed to set intrusion. */
	INTRUSION_STATE_CLEAR_FAILED = INTRUSION_STATE_ERROR (0x03),			/**< Failed to clear intrusion. */
	INTRUSION_STATE_CHECK_FAILED = INTRUSION_STATE_ERROR (0x04),			/**< Failed to check intrusion state. */
	INTRUSION_STATE_CHECK_DEFERRED = INTRUSION_STATE_ERROR (0x05),			/**< State checking will be done in the background. */
	INTRUSION_STATE_REMOTE_REQUEST_FAILED = INTRUSION_STATE_ERROR (0x06),	/**< Request to remote component failed. */
};


#endif /* INTRUSION_STATE_H_ */
