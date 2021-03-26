// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_manager.h"
#include "manifest/manifest_logging.h"


/**
 * Add an observer to be notified of CFM management events.  An observer can only be added to the
 * list once.  The order in which observers are notified is not guaranteed to be the same as the
 * order in which they were added.
 *
 * @param manager The manager to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was added for notifications or an error code.
 */
int cfm_manager_add_observer (struct cfm_manager *manager, struct cfm_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->observable, observer);
}

/**
 * Remove an observer so it will no longer be notified of CFM management events.
 *
 * @param manager The manager to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int cfm_manager_remove_observer (struct cfm_manager *manager, struct cfm_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->observable, observer);
}

/**
 * Initialize the base CFM manager.
 *
 * @param manager The manager to initialize.
 * @param hash The hash engine to generate measurement data.
 *
 * @return 0 if the CFM manager was initialized successfully or an error code.
 */
int cfm_manager_init (struct cfm_manager *manager, struct hash_engine *hash)
{
	int status;

	memset (manager, 0, sizeof (struct cfm_manager));

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	return manifest_manager_init (&manager->base, hash);
}

/**
 * Release the resources used by base CFM manager.
 *
 * @param manager The manager to release.
 */
void cfm_manager_release (struct cfm_manager *manager)
{
	if (manager) {
		observable_release (&manager->observable);
	}
}

/**
 * Notify all observers of an event for a CFM.  The CFM will be released to the manager upon
 * completion.
 *
 * @param manager The manager generating the event.
 * @param cfm The CFM the event is for.
 * @param callback_offset The offset in the observer structure for the notification to call.
 */
static void cfm_manager_notify_observers (struct cfm_manager *manager, struct cfm *cfm,
	size_t callback_offset)
{
	if (!cfm) {
		/* No CFM so no event notification. */
		return;
	}

	observable_notify_observers_with_ptr (&manager->observable, callback_offset, cfm);

	manager->free_cfm (manager, cfm);
}

/**
 * Notify observers that a new CFM has been verified and is now pending.
 *
 * @param manager The manager generating the event.
 */
void cfm_manager_on_cfm_verified (struct cfm_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_CFM_VERIFIED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	cfm_manager_notify_observers (manager, manager->get_pending_cfm (manager),
		offsetof (struct cfm_observer, on_cfm_verified));
}

/**
 * Notify observers that a new CFM has been activated.
 *
 * @param manager The manager generating the event.
 */
void cfm_manager_on_cfm_activated (struct cfm_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_CFM_ACTIVATED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	cfm_manager_notify_observers (manager, manager->get_active_cfm (manager),
		offsetof (struct cfm_observer, on_cfm_activated));
}

/**
 * Notify observers that the active CFM has been cleared.
 *
 * @param manager The manager generating the event.
 */
void cfm_manager_on_clear_active (struct cfm_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_CFM_CLEAR_ACTIVE_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	observable_notify_observers (&manager->observable,
		offsetof (struct cfm_observer, on_clear_active));
}

/**
 * Get the data used for CFM ID measurement.  The CFM instance must be released with the
 * manager.
 *
 * @param manager The CFM manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer. Updated with actual length
 * @param total_len Total length of CFM ID measurement
 *
 *@return length of the measured data if successfully retrieved or an error code.
 */
int cfm_manager_get_id_measured_data (struct cfm_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len)
{
	int status;
	struct cfm *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_cfm (manager);
	if (active == NULL) {
		status = manifest_manager_get_id_measured_data (NULL, offset, buffer, length, total_len);
	}
	else {
		status = manifest_manager_get_id_measured_data (&active->base, offset, buffer, length,
			total_len);
		manager->free_cfm (manager, active);
	}

	return status;
}

/**
 * Get the data used for CFM platform ID measurement.  The CFM instance must be released with the
 * manager.
 *
 * @param manager The CFM manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of manifest platform ID measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int cfm_manager_get_platform_id_measured_data (struct cfm_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;
	struct cfm *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_cfm (manager);
	if (active == NULL) {
		status = manifest_manager_get_platform_id_measured_data (NULL, offset, buffer, length,
			total_len);
	}
	else {
		status = manifest_manager_get_platform_id_measured_data (&active->base, offset, buffer,
			length, total_len);
		manager->free_cfm (manager, active);
	}

	return status;
}

/**
 * Get the data used for CFM measurement.  The CFM instance must be released with the
 * manager.
 *
 * @param manager The PFM manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of measured data
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int cfm_manager_get_cfm_measured_data (struct cfm_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len)
{
	int status;
	struct cfm *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_cfm (manager);
	if (active == NULL) {
		status = manifest_manager_get_manifest_measured_data (&manager->base, NULL, offset, buffer,
			length, total_len);
	}
	else {
		status = manifest_manager_get_manifest_measured_data (&manager->base, &active->base, offset,
			buffer, length, total_len);
		manager->free_cfm (manager, active);
	}

	return status;
}
