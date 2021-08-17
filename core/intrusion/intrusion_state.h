// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef INTRUSION_STATE_H_
#define INTRUSION_STATE_H_

#include <stdint.h>
#include <stdbool.h>
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
	 * Check intrusion state for the device.
	 * 
	 * @param intrusion The intrusion state instance being tracked.
	 * 
	 * @return 0 if no intrusion, 1 if intrusion detected, or an error code.
	 */
	int (*check) (struct intrusion_state *intrusion);
};


#define	INSTRUSION_STATE_ERROR(code)		ROT_ERROR (ROT_MODULE_INTRUSION_STATE, code)

/**
 * Error codes for intrusion state information.
 */
enum {
	INTRUSION_STATE_INVALID_ARGUMENT = INSTRUSION_STATE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	INTRUSION_STATE_NO_MEMORY = INSTRUSION_STATE_ERROR (0x01),				/**< Could not allocate memory for the data buffer. */
};


#endif // INTRUSION_STATE_H_
