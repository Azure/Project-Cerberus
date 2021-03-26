// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_observer_pcr.h"
#include "manifest/manifest_logging.h"


static void cfm_observer_pcr_on_cfm_activated (struct cfm_observer *observer, struct cfm *active)
{
	struct cfm_observer_pcr *pcr = (struct cfm_observer_pcr*) observer;

	manifest_pcr_record_manifest_measurement (&pcr->pcr, &active->base);
}

static void cfm_observer_pcr_on_clear_active (struct cfm_observer *observer)
{
	struct cfm_observer_pcr *pcr = (struct cfm_observer_pcr*) observer;

	manifest_pcr_record_manifest_measurement (&pcr->pcr, NULL);
}

/**
 * Initialize the CFM observer for updating PCR entries.
 *
 * @param observer The observer to initialize.
 * @param hash The hash engine to use for generating PCR measurements.
 * @param store The PCR store to update as the CFM changes.
 * @param manifest_measurement The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement The identifier for the manifest ID measurement in the PCR.
 * @param platform_id_measurement The identifier for the manifest platform ID measurement in the PCR.
 *
 * @return 0 if the observer was successfully initialized or an error code.
 */
int cfm_observer_pcr_init (struct cfm_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t platform_id_measurement)
{
	int status;

	if ((observer == NULL) || (hash == NULL) || (store == NULL)) {
		return CFM_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct cfm_observer_pcr));

	status = manifest_pcr_init (&observer->pcr, hash, store, manifest_measurement,
		manifest_id_measurement, platform_id_measurement, CFM_OBSERVER_MEASUREMENTS_NOT_UNIQUE);
	if (status != 0) {
		return status;
	}

	observer->base.on_cfm_activated = cfm_observer_pcr_on_cfm_activated;
	observer->base.on_clear_active = cfm_observer_pcr_on_clear_active;

	return 0;
}

/**
 * Release the resources used by the CFM observer.
 *
 * @param observer The observer to release.
 */
void cfm_observer_pcr_release (struct cfm_observer_pcr *observer)
{
	if (observer) {
		manifest_pcr_release (&observer->pcr);
	}
}

/**
 * Force the PCR to be updated with the current active CFM measurement.
 *
 * @param observer The observer for the PCR to update.
 * @param manager The manager for the CFM measurement to update.
 */
void cfm_observer_pcr_record_measurement (struct cfm_observer_pcr *observer,
	struct cfm_manager *manager)
{
	struct cfm *active;
	struct cfm_observer_pcr *pcr = (struct cfm_observer_pcr*) observer;

	if ((observer == NULL) || (manager == NULL)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_CFM_RECORD_INVALID, CFM_OBSERVER_INVALID_ARGUMENT, 0);
		return;
	}

	active = manager->get_active_cfm (manager);
	if (active) {
		manifest_pcr_record_manifest_measurement (&pcr->pcr, &active->base);
		manager->free_cfm (manager, active);
	}
	else {
		manifest_pcr_record_manifest_measurement (&pcr->pcr, NULL);
	}
}
