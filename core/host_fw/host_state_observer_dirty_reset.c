// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_state_observer_dirty_reset.h"


static void host_state_observer_dirty_reset_on_inactive_dirty (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_dirty_reset *reset =
		(struct host_state_observer_dirty_reset*) observer;

	if (host_state_manager_is_inactive_dirty (manager)) {
		reset->control->hold_processor_in_reset (reset->control, true);
	}
}

/**
 * Initialize a host state observer to assert the host reset control when the flash is dirty.
 *
 * @param observer The observer to initialize.
 * @param control The interface for host processor control signals.
 *
 * @return 0 if the observer was successfully initialized or an error code.
 */
int host_state_observer_dirty_reset_init (struct host_state_observer_dirty_reset *observer,
	struct host_control *control)
{
	if ((observer == NULL) || (control == NULL)) {
		return HOST_STATE_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct host_state_observer_dirty_reset));

	observer->base.on_inactive_dirty = host_state_observer_dirty_reset_on_inactive_dirty;

	observer->control = control;

	return 0;
}

/**
 * Release the resources used by the pending PFM reset observer.
 *
 * @param observer The observer to release.
 */
void host_state_observer_dirty_reset_release (struct host_state_observer_dirty_reset *observer)
{

}
