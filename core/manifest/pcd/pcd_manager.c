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
 * @param hash The hash engine to generate measurement data.
 *
 * @return 0 if the PCD manager was initialized successfully or an error code.
 */
int pcd_manager_init (struct pcd_manager *manager, struct hash_engine *hash)
{
	int status;

	memset (manager, 0, sizeof (struct pcd_manager));

	status = observable_init (&manager->observable);
	if (status != 0) {
		return status;
	}

	return manifest_manager_init (&manager->base, hash);
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
 * Notify observers that a new PCD has been verified and is now pending.
 *
 * @param manager The manager generating the event.
 * @param pending The pending PCD that was verified.
 */
void pcd_manager_on_pcd_verified (struct pcd_manager *manager, struct pcd *pending)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_VERIFIED_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	pcd_manager_notify_observers (manager, pending,
		offsetof (struct pcd_observer, on_pcd_verified));
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

/**
 * Notify observers that the active PCD has been cleared.
 *
 * @param manager The manager generating the event.
 */
void pcd_manager_on_clear_active (struct pcd_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_CLEAR_ACTIVE_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);
		return;
	}

	observable_notify_observers (&manager->observable,
		offsetof (struct pcd_observer, on_clear_active));
}

/**
 * Get the data used for PCD ID measurement.  The PCD instance must be released with the
 * manager.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of PCD ID measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_id_measured_data (struct pcd_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len)
{
	int status;
	struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_get_id_measured_data (NULL, offset, buffer, length, total_len);
	}
	else {
		status = manifest_manager_get_id_measured_data (&active->base, offset, buffer, length,
			total_len);
		manager->free_pcd (manager, active);
	}

	return status;
}

/**
 * Get the data used for PCD Platform ID measurement.  The PCD instance must be released with the
 * manager.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of manifest platform ID measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_platform_id_measured_data (struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;
	struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_get_platform_id_measured_data (NULL, offset, buffer, length,
			total_len);
	}
	else {
		status = manifest_manager_get_platform_id_measured_data (&active->base, offset, buffer,
			length, total_len);
		manager->free_pcd (manager, active);
	}

	return status;
}

/**
 * Get the data used for PCD measurement.  The PCD instance must be released with the
 * manager.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of measured data
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_pcd_measured_data (struct pcd_manager *manager, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len)
{
	int status;
	struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_get_manifest_measured_data (&manager->base, NULL, offset, buffer,
			length, total_len);
	}
	else {
		status = manifest_manager_get_manifest_measured_data (&manager->base, &active->base, offset,
			buffer, length, total_len);
		manager->free_pcd (manager, active);
	}

	return status;
}
