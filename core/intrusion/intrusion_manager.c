// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "intrusion_manager.h"
#include "intrusion_logging.h"


/**
 * Update the intrusion state measurement in the PCR.
 *
 * @param manager The intrusion manager to update.
 * @param value The value to use for the measurement event data.
 * @param force_data True to force the event data to be changed even if the measurement fails to
 * update.
 *
 * @return 0 if the measurement was successfully updated or an error code.
 */
int intrusion_manager_update_measurement (struct intrusion_manager *manager, uint8_t value,
	bool force_data)
{
	int status;

	status = pcr_store_update_versioned_buffer (manager->pcr, manager->hash,
		manager->measurement, &value, sizeof (value), true, INTRUSION_MANAGER_MEASUREMENT_VERSION);
	if ((status == 0) || force_data) {
		manager->event_data.data.value_1byte = value;
	}

	return status;
}

static int intrusion_manager_handle_intrusion (struct intrusion_manager *manager)
{
	int pcr_status;
	int state_status;

	if (manager == NULL) {
		return INTRUSION_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	/* On error, the data won't match the measurement, but we want to be sure we aren't falsely
	 * reporting a healthy state. */
	pcr_status = intrusion_manager_update_measurement (manager, INTRUSION_MANAGER_INTRUSION, true);

	state_status = manager->state->set (manager->state);

	platform_mutex_unlock (&manager->lock);
	return (pcr_status == 0) ? state_status : pcr_status;
}

static int intrusion_manager_reset_intrusion (struct intrusion_manager *manager)
{
	int status;

	if (manager == NULL) {
		return INTRUSION_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	status = manager->state->clear (manager->state);
	if (status == 0) {
		status = intrusion_manager_update_measurement (manager, INTRUSION_MANAGER_NO_INTRUSION,
			false);
	}

	platform_mutex_unlock (&manager->lock);
	return status;
}

/**
 * Check the current intrusion state and update the intrusion measurement.
 *
 * @param manager The intrusion manager to use for the update.
 * @param allow_deferred Allow state management to provide asynchronous notifications.
 *
 * @return 0 if the update was successful or an error code.  If the state checking is deferred while
 * deferred updates are allowed, this call will return 0.  If deferred updates are not allowed, it
 * will return an error code.
 */
int intrusion_manager_update_intrusion_state (struct intrusion_manager *manager,
	bool allow_deferred)
{
	uint8_t value;
	int check_status;
	int pcr_status = 0;
	bool force_data = true;

	if (manager == NULL) {
		return INTRUSION_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->lock);

	check_status = manager->state->check (manager->state);
	switch (check_status) {
		case 0:
			value = INTRUSION_MANAGER_NO_INTRUSION;
			/* Only in the case of no intrusion do we want to make event data updating contingent on
			 * measurement success.  Otherwise, we could be falsely reporting a healthy system. */
			force_data = false;
			break;

		case 1:
			value = INTRUSION_MANAGER_INTRUSION;
			check_status = 0;
			break;

		case INTRUSION_STATE_CHECK_DEFERRED:
			if (allow_deferred) {
				check_status = 0;
				goto exit;
			}

			value = INTRUSION_MANAGER_UNKNOWN;
			break;

		default:
			value = INTRUSION_MANAGER_UNKNOWN;
			break;
	}

	pcr_status = intrusion_manager_update_measurement (manager, value, force_data);

exit:
	platform_mutex_unlock (&manager->lock);
	return (check_status == 0) ? pcr_status : check_status;
}

static int intrusion_manager_check_state (struct intrusion_manager *manager)
{
	return intrusion_manager_update_intrusion_state (manager, false);
}

/**
 * Initialize a manager for intrusion detection.
 *
 * @param manager The intrusion manager to initialize.
 * @param state The handler for persisting intrusion state.
 * @param hash Hash engine to use for PCR updates.
 * @param pcr The PCR manager that will be used to report intrusion state.
 * @param measurement The measurement ID for the intrusion state.
 *
 * @return 0 if the intrusion manager was successfully initialized or an error code.
 */
int intrusion_manager_init (struct intrusion_manager *manager, struct intrusion_state *state,
    struct hash_engine *hash, struct pcr_store *pcr, uint16_t measurement)
{
	int status;

	if ((manager == NULL) || (state == NULL) || (hash == NULL) || (pcr == NULL)) {
		return INTRUSION_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct intrusion_manager));

	status = platform_mutex_init (&manager->lock);
	if (status != 0) {
		return status;
	}

	manager->handle_intrusion = intrusion_manager_handle_intrusion;
	manager->reset_intrusion = intrusion_manager_reset_intrusion;
	manager->check_state = intrusion_manager_check_state;

	manager->state = state;
	manager->hash = hash;
	manager->pcr = pcr;
	manager->measurement = measurement;

	manager->event_data.type = PCR_DATA_TYPE_1BYTE;
	status = pcr_store_set_measurement_data (pcr, measurement, &manager->event_data);
	if (status != 0) {
		goto error;
	}

	status = intrusion_manager_update_measurement (manager, INTRUSION_MANAGER_UNKNOWN, true);
	if (status != 0) {
		goto unregister;
	}

	return 0;

unregister:
	/* Remove the linage to the PCR measurement on a failure. */
	pcr_store_set_measurement_data (pcr, measurement, NULL);
error:
	platform_mutex_free (&manager->lock);
	return status;
}

/**
 * Release the resources used by an intrusion manager.
 *
 * @param manager The intrusion manager to release.
 */
void intrusion_manager_release (struct intrusion_manager *manager)
{
	if (manager) {
		platform_mutex_free (&manager->lock);
	}
}
