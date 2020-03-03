// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pcd_manager.h"
#include "manifest/manifest_logging.h"


/**
 * Add an observer to be notified of PCD management events. An observer can only be added to the
 * list once. The order in which observers are notified is not guaranteed to be the same as the
 * order in which they were added.
 *
 * @param manager The manager to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was added for notifications or an error code.
 */
int pcd_manager_add_observer (struct pcd_manager *manager, struct pcd_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->observable, observer);
}

/**
 * Remove an observer so it will no longer be notified of PCD management events.
 *
 * @param manager The manager to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int pcd_manager_remove_observer (struct pcd_manager *manager, struct pcd_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->observable, observer);
}

/**
 * Initialize the base PCD manager.
 *
 * @param manager The manager to initialize.
 *
 * @return 0 if the PCD manager was initialized successfully or an error code.
 */
int pcd_manager_init (struct pcd_manager *manager)
{
	int status;

	memset (manager, 0, sizeof (struct pcd_manager));

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Release the resources used by base PCD manager.
 *
 * @param manager The manager to release.
 */
void pcd_manager_release (struct pcd_manager *manager)
{
	if (manager) {
		observable_release (&manager->observable);
	}
}

/**
 * Notify all observers of an event for a PCD. The PCD will be released to the manager upon
 * completion.
 *
 * @param manager The manager generating the event.
 * @param pcd The PCD the event is for.
 * @param callback_offset The offset in the observer structure for the notification to call.
 */
static void pcd_manager_notify_observers (struct pcd_manager *manager, struct pcd *pcd,
	size_t callback_offset)
{
	if (!pcd) {
		/* No PCD so no event notification. */
		return;
	}

	observable_notify_observers_with_ptr (&manager->observable, callback_offset, pcd);

	manager->free_pcd (manager, pcd);
}

/**
 * Notify observers that a new CFM has been verified and is now pending.
 *
 * @param manager The manager generating the event.
 */
void pcd_manager_on_pcd_verified (struct pcd_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_VERIFIED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	pcd_manager_notify_observers (manager, NULL, offsetof (struct pcd_observer, on_pcd_verified));
}

/**
 * Notify observers that a new PCD has been activated.
 *
 * @param manager The manager generating the event.
 */
void pcd_manager_on_pcd_activated (struct pcd_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_ACTIVATED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	pcd_manager_notify_observers (manager, manager->get_active_pcd (manager),
		offsetof (struct pcd_observer, on_pcd_activated));
}
