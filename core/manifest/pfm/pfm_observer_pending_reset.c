// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_observer_pending_reset.h"
#include "manifest/manifest_logging.h"


static void pfm_observer_pending_reset_on_pfm_verified (struct pfm_observer *observer,
	struct pfm *pending)
{
	struct pfm_observer_pending_reset *reset = (struct pfm_observer_pending_reset*) observer;
	int status;

	status = reset->control->hold_processor_in_reset (reset->control, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PENDING_RESET_FAIL, status, 0);
	}
}

static void pfm_observer_pending_reset_on_clear_active (struct pfm_observer *observer)
{
	pfm_observer_pending_reset_on_pfm_verified (observer, NULL);
}

/**
 * Initialize a PFM observer to assert host reset on pending PFM verification.
 *
 * @param observer The observer to initialize.
 * @param control The interface for host processor control signals.
 *
 * @return 0 if the observer was successfully initialized or an error code.
 */
int pfm_observer_pending_reset_init (struct pfm_observer_pending_reset *observer,
	struct host_control *control)
{
	if ((observer == NULL) || (control == NULL)) {
		return PFM_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct pfm_observer_pending_reset));

	observer->base.on_pfm_verified = pfm_observer_pending_reset_on_pfm_verified;
	observer->base.on_clear_active = pfm_observer_pending_reset_on_clear_active;

	observer->control = control;

	return 0;
}

/**
 * Release the resources used by the pending PFM reset observer.
 *
 * @param observer The observer to release.
 */
void pfm_observer_pending_reset_release (struct pfm_observer_pending_reset *observer)
{

}
