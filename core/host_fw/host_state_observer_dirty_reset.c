// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_logging.h"
#include "host_state_observer_dirty_reset.h"
#include "common/unused.h"


void host_state_observer_dirty_reset_on_read_only_flash (const struct host_state_observer *observer,
	const struct host_state_manager *manager)
{
	const struct host_state_observer_dirty_reset *reset =
		(const struct host_state_observer_dirty_reset*) observer;
	int status;

	if (host_state_manager_has_read_only_flash_override (manager)) {
		/* If an read-only override has been applied, assert reset control to allow for any possible
		 * flash switching. */
		status = reset->control->hold_processor_in_reset (reset->control, true);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_DIRTY_RESET_ERROR, status, 0);
		}
	}
}

void host_state_observer_dirty_reset_on_inactive_dirty (const struct host_state_observer *observer,
	const struct host_state_manager *manager)
{
	const struct host_state_observer_dirty_reset *reset =
		(const struct host_state_observer_dirty_reset*) observer;
	int status;

	if (host_state_manager_is_inactive_dirty (manager)) {
		status = reset->control->hold_processor_in_reset (reset->control, true);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_HOST_FW,
				HOST_LOGGING_DIRTY_RESET_ERROR, status, 0);
		}
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
	const struct host_control *control)
{
	if ((observer == NULL) || (control == NULL)) {
		return HOST_STATE_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct host_state_observer_dirty_reset));

	observer->base.on_read_only_flash = host_state_observer_dirty_reset_on_read_only_flash;
	observer->base.on_inactive_dirty = host_state_observer_dirty_reset_on_inactive_dirty;

	observer->control = control;

	return 0;
}

/**
 * Release the resources used by the pending PFM reset observer.
 *
 * @param observer The observer to release.
 */
void host_state_observer_dirty_reset_release (
	const struct host_state_observer_dirty_reset *observer)
{
	UNUSED (observer);
}
