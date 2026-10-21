// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
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
int pcd_manager_add_observer (const struct pcd_manager *manager,
	const struct pcd_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->state->observable, (void*) observer);
}

/**
 * Remove an observer so it will no longer be notified of PCD management events.
 *
 * @param manager The manager to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int pcd_manager_remove_observer (const struct pcd_manager *manager,
	const struct pcd_observer *observer)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->state->observable, (void*) observer);
}

/**
 * Initialize the base PCD manager.
 *
 * @param manager The manager to initialize.
 * @param state Variable context for the PCD manager.  This must be uninitialized.
 * @param hash The hash engine to generate measurement data.
 *
 * @return 0 if the PCD manager was initialized successfully or an error code.
 */
int pcd_manager_init (struct pcd_manager *manager, struct pcd_manager_state *state,
	const struct hash_engine *hash)
{
	int status;

	memset (manager, 0, sizeof (struct pcd_manager));

	status = manifest_manager_init (&manager->base, hash);
	if (status != 0) {
		return status;
	}

	manager->state = state;

	return pcd_manager_init_state (manager);
}

/**
 * Initialize only the variable state for a base PCD manager.  The rest of the manager is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int pcd_manager_init_state (const struct pcd_manager *manager)
{
	if (manager->state == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager->state, 0, sizeof (*manager->state));

	return observable_init (&manager->state->observable);
}

/**
 * Release the resources used by base PCD manager.
 *
 * @param manager The manager to release.
 */
void pcd_manager_release (const struct pcd_manager *manager)
{
	if (manager) {
		observable_release (&manager->state->observable);
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
static void pcd_manager_notify_observers (const struct pcd_manager *manager, const struct pcd *pcd,
	size_t callback_offset)
{
	if (!pcd) {
		/* No PCD so no event notification. */
		return;
	}

	observable_notify_observers_with_ptr (&manager->state->observable, callback_offset,
		(void*) pcd);

	manager->free_pcd (manager, pcd);
}

/**
 * Notify observers that a new PCD has been verified and is now pending.
 *
 * @param manager The manager generating the event.
 * @param pending The pending PCD that was verified.
 */
void pcd_manager_on_pcd_verified (const struct pcd_manager *manager, const struct pcd *pending)
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
void pcd_manager_on_pcd_activated (const struct pcd_manager *manager)
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
void pcd_manager_on_clear_active (const struct pcd_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_CLEAR_ACTIVE_EVENT_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);

		return;
	}

	observable_notify_observers (&manager->state->observable,
		offsetof (struct pcd_observer, on_clear_active));
}

/**
 * Notify observers that a PCD activation request has been received.
 *
 * @param manager The manager generating the event.
 */
void pcd_manager_on_pcd_activation_request (const struct pcd_manager *manager)
{
	if (manager == NULL) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_ACTIVATION_REQUEST_FAIL, MANIFEST_MANAGER_INVALID_ARGUMENT, 0);

		return;
	}

	observable_notify_observers (&manager->state->observable,
		offsetof (struct pcd_observer, on_pcd_activation_request));
}

/**
 * Get the data used for PCD ID measurement.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of PCD ID measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_id_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;
	const struct pcd *active;

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
 * Update a hash context with the data used for the PCD ID measurement.
 *
 * @param manager The PCD manager to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int pcd_manager_hash_id_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash)
{
	int status;
	const struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_hash_id_measured_data (NULL, hash);
	}
	else {
		status = manifest_manager_hash_id_measured_data (&active->base, hash);
		manager->free_pcd (manager, active);
	}

	return status;
}

/**
 * Get the data used for PCD Platform ID measurement.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of manifest platform ID measurement
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_platform_id_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;
	const struct pcd *active;

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
 * Update a hash context with the data used for the PCD platform ID measurement.
 *
 * @param manager The PCD manager to query.
 * @param hash Hash engine to update.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int pcd_manager_hash_platform_id_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash)
{
	int status;
	const struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_hash_platform_id_measured_data (NULL, hash);
	}
	else {
		status = manifest_manager_hash_platform_id_measured_data (&active->base, hash);
		manager->free_pcd (manager, active);
	}

	return status;
}

/**
 * Get the data used for PCD measurement.
 *
 * @param manager The PCD manager to query
 * @param offset The offset to read data from
 * @param buffer The output buffer to be filled with measured data
 * @param length Maximum length of the buffer
 * @param total_len Total length of measured data
 *
 * @return Length of the measured data if successfully retrieved or an error code.
 */
int pcd_manager_get_pcd_measured_data (const struct pcd_manager *manager, size_t offset,
	uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;
	const struct pcd *active;

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

/**
 * Update a hash context with the data used for the PCD measurement.
 *
 * NOTE:  When using this function to hash the PCD measurement, it must be guaranteed that the hash
 * context used by the PCD manager be different from the one passed into this function as an
 * argument.
 *
 * @param manager The PCD manager to query.
 * @param hash Hash engine to update.  This must be different from the hash engine contained in the
 * PCD manager.
 *
 * @return 0 if the hash was updated successfully or an error code.
 */
int pcd_manager_hash_pcd_measured_data (const struct pcd_manager *manager,
	const struct hash_engine *hash)
{
	int status;
	const struct pcd *active;

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	active = manager->get_active_pcd (manager);
	if (active == NULL) {
		status = manifest_manager_hash_manifest_measured_data (&manager->base, NULL, hash);
	}
	else {
		status = manifest_manager_hash_manifest_measured_data (&manager->base, &active->base, hash);
		manager->free_pcd (manager, active);
	}

	return status;
}
