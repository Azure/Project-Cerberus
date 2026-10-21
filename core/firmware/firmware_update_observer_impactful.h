// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_H_
#define FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_H_

#include "firmware_update_observer.h"
#include "impactful_update_interface.h"


/**
 * Observer for firmware updates to check for impactful updates and block unauthorized updates.
 */
struct firmware_update_observer_impactful {
	struct firmware_update_observer base;				/**< Base notification interface. */
	const struct impactful_update_interface *update;	/**< Handler for impactful updates. */
};


int firmware_update_observer_impactful_init (struct firmware_update_observer_impactful *observer,
	const struct impactful_update_interface *impactful);
void firmware_update_observer_impactful_release (
	const struct firmware_update_observer_impactful *observer);


/* Treat this as an extension of the impactful update interface and use error codes from that
 * module. */


#endif	/* FIRMWARE_UPDATE_OBSERVER_IMPACTFUL_H_ */
