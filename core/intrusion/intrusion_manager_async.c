// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "intrusion_manager_async.h"
#include "intrusion_logging.h"
#include "common/type_cast.h"


static int intrusion_manager_async_check_state (struct intrusion_manager *manager)
{
	return intrusion_manager_update_intrusion_state (manager, true);
}

/**
 * Update the intrusion state measurement in the PCR.
 *
 * @param observer The observer for the manager used to update the intrusion state measurement.
 * @param value The value to use for the measurement event data.
 * @param force_data True to force the event data to be changed even if the measurement fails to
 * update.
 * @param log_entry Id code of the event in the log.
 */
static void intrusion_manager_async_update_measurement (struct intrusion_state_observer *observer,
	uint8_t value, bool force_data, uint8_t log_entry)
{
	struct intrusion_manager_async *manager =
		TO_DERIVED_TYPE (observer, struct intrusion_manager_async, base_observer);
	int status;

	platform_mutex_lock (&manager->base.lock);

	status = intrusion_manager_update_measurement (&manager->base, value, force_data);

	platform_mutex_unlock (&manager->base.lock);

	debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
		DEBUG_LOG_COMPONENT_INTRUSION, log_entry, status, 0);
}

static void intrusion_manager_async_on_intrusion (struct intrusion_state_observer *observer)
{
	/* On error, the data won't match the measurement, but we want to be sure we aren't falsely
	 * reporting a healthy state. */
	intrusion_manager_async_update_measurement (observer, INTRUSION_MANAGER_INTRUSION, true,
		INTRUSION_LOGGING_INTRUSION_NOTIFICATION);
}

static void intrusion_manager_async_on_no_intrusion (struct intrusion_state_observer *observer)
{
	intrusion_manager_async_update_measurement (observer, INTRUSION_MANAGER_NO_INTRUSION, false,
		INTRUSION_LOGGING_NO_INTRUSION_NOTIFICATION);
}

static void intrusion_manager_async_on_error (struct intrusion_state_observer *observer)
{
	/* On error, the data won't match the measurement, but we want to be sure we aren't falsely
	 * reporting a healthy state. */
	intrusion_manager_async_update_measurement (observer, INTRUSION_MANAGER_UNKNOWN, true,
		INTRUSION_LOGGING_ERROR_NOTIFICATION);
}

/**
 * Initialize a manager for handling intrusion events that supports receiving notifications about
 * intrusion state.
 *
 * Registration for the state events needs to be managed externally.
 *
 * @param manager The intrusion manager to initialize.
 * @param state The handler for persisting intrusion state.
 * @param hash Hash engine to use for PCR updates.
 * @param pcr The PCR manager that will be used to report intrusion state.
 * @param measurement The measurement ID for the intrusion state.
 *
 * @return 0 if the intrusion manager was successfully initialized or an error code.
 */
int intrusion_manager_async_init (struct intrusion_manager_async *manager,
	struct intrusion_state *state, struct hash_engine *hash, struct pcr_store *pcr,
	uint16_t measurement)
{
	int status;

	status = intrusion_manager_init (&manager->base, state, hash, pcr, measurement);

	if (status == 0) {
		manager->base.check_state = intrusion_manager_async_check_state;

		manager->base_observer.on_intrusion = intrusion_manager_async_on_intrusion;
		manager->base_observer.on_no_intrusion = intrusion_manager_async_on_no_intrusion;
		manager->base_observer.on_error = intrusion_manager_async_on_error;
	}

	return status;
}

/**
 * Release the resources used by an intrusion manager.
 *
 * @param manager The intrusion manager to release.
 */
void intrusion_manager_async_release (struct intrusion_manager_async *manager)
{
	intrusion_manager_release (&manager->base);
}
