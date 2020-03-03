// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_manager.h"
#include "manifest/manifest_logging.h"


/**
 * Add an observer to be notified of PFM management events.  An observer can only be added to the
 * list once.  The order in which observers are notified is not guaranteed to be the same as the
 * order in which they were added.
 *
 * @param manager The manager to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was added for notifications or an error code.
 */
int pfm_manager_add_observer (struct pfm_manager *manager, struct pfm_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->observable, observer);
}

/**
 * Remove an observer so it will no longer be notified of PFM management events.
 *
 * @param manager The manager to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int pfm_manager_remove_observer (struct pfm_manager *manager, struct pfm_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->observable, observer);
}

/**
 * Initialize the base PFM manager.
 *
 * @param manager The manager to initialize.
 * @param port The port identifier for the manager.  A negative value will use the default ID.
 *
 * @return 0 if the PFM manager was initialized successfully or an error code.
 */
int pfm_manager_init (struct pfm_manager *manager, int port)
{
	int status;

	memset (manager, 0, sizeof (struct pfm_manager));

	if (port > 0) {
		manifest_manager_set_port (&manager->base, port);
	}

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Release the resources used by base PFM manager.
 *
 * @param manager The manager to release.
 */
void pfm_manager_release (struct pfm_manager *manager)
{
	if (manager) {
		observable_release (&manager->observable);
	}
}

/**
 * Notify all observers of an event for a PFM.  The PFM will be released to the manager upon
 * completion.
 *
 * @param manager The manager generating the event.
 * @param pfm The PFM the event is for.
 * @param callback_offset The offset in the observer structure for the notification to call.
 */
static void pfm_manager_notify_observers (struct pfm_manager *manager, struct pfm *pfm,
	size_t callback_offset)
{
	if (!pfm) {
		/* No PFM so no event notification. */
		return;
	}

	observable_notify_observers_with_ptr (&manager->observable, callback_offset, pfm);

	manager->free_pfm (manager, pfm);
}

/**
 * Notify observers that a new PFM has been verified and is now pending.
 *
 * @param manager The manager generating the event.
 */
void pfm_manager_on_pfm_verified (struct pfm_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PFM_VERIFIED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	pfm_manager_notify_observers (manager, manager->get_pending_pfm (manager),
		offsetof (struct pfm_observer, on_pfm_verified));
}

/**
 * Notify observers that a new PFM has been activated.
 *
 * @param manager The manager generating the event.
 */
void pfm_manager_on_pfm_activated (struct pfm_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PFM_ACTIVATED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	pfm_manager_notify_observers (manager, manager->get_active_pfm (manager),
		offsetof (struct pfm_observer, on_pfm_activated));
}
