// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_update_observer_impactful.h"
#include "common/unused.h"


void firmware_update_observer_impactful_on_update_start (
	const struct firmware_update_observer *observer, int *update_allowed)
{
	const struct firmware_update_observer_impactful *impactful =
		(const struct firmware_update_observer_impactful*) observer;

	/* Only check if the update is allowed if some other observer has not already disallowed it. */
	if (*update_allowed == 0) {
		*update_allowed = impactful->update->is_update_allowed (impactful->update);
	}
}

/**
 * Initialize a firmware update observer used to block impactful firmware updates.
 *
 * @param observer The observer to initialize.
 * @param impactful The impactful update handler that should be used to determine if an update
 * should be allowed.
 *
 * @return 0 if the observer was initialized successfully or an error code.
 */
int firmware_update_observer_impactful_init (struct firmware_update_observer_impactful *observer,
	const struct impactful_update_interface *impactful)
{
	if ((observer == NULL) || (impactful == NULL)) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (*observer));

	observer->base.on_update_start = firmware_update_observer_impactful_on_update_start;

	observer->update = impactful;

	return 0;
}

/**
 * Release the resources used for an impactful update observer.
 *
 * @param observer The observer to release.
 */
void firmware_update_observer_impactful_release (
	const struct firmware_update_observer_impactful *observer)
{
	UNUSED (observer);
}
