// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_STATIC_H_
#define FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_STATIC_H_

#include "firmware_update_observer_impactful.h"


/* Internal functions declared to allow for static initialization. */
void firmware_update_observer_impactful_on_update_start (
	const struct firmware_update_observer *observer, int *update_allowed);


/**
 * Constant initializer for the firmware update event handlers.
 */
#define	FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_API_INIT  { \
		.on_update_start = firmware_update_observer_impactful_on_update_start, \
		.on_prepare_update = NULL, \
		.on_update_applied = NULL, \
	}


/**
 * Initialize a static instance for a firmware update observer used to block impactful firmware
 * updates.
 *
 * There is no validation done on the arguments.
 *
 * @param impactful_ptr The impactful update handler that should be used to determine if an update
 * should be allowed.
 */
#define	firmware_update_observer_impactful_static_init(impactful_ptr)	{ \
		.base = FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_API_INIT, \
		.update = impactful_ptr, \
	}


#endif	/* FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_STATIC_H_ */
