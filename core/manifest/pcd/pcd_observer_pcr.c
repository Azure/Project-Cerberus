// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pcd_observer_pcr.h"
#include "manifest/manifest_logging.h"


static void pcd_observer_pcr_on_pcd_activated (struct pcd_observer *observer, struct pcd *active)
{
	struct pcd_observer_pcr *pcr = (struct pcd_observer_pcr*) observer;

	manifest_pcr_record_manifest_measurement (&pcr->pcr, &active->base);
}

static void pcd_observer_pcr_on_clear_active (struct pcd_observer *observer)
{
	struct pcd_observer_pcr *pcr = (struct pcd_observer_pcr*) observer;

	manifest_pcr_record_manifest_measurement (&pcr->pcr, NULL);
}

/**
 * Initialize the PCD observer for updating PCR entries.
 *
 * @param observer The observer to initialize.
 * @param hash The hash engine to use for generating PCR measurements.
 * @param store The PCR store to update as the PCD changes.
 * @param manifest_measurement The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement The identifier for the manifest ID measurement in the PCR.
 * @param platform_id_measurement The identifier for the manifest platform ID measurement in the PCR.
 *
 * @return 0 if the observer was successfully initialized or an error code.
 */
int pcd_observer_pcr_init (struct pcd_observer_pcr *observer, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t platform_id_measurement)
{
	int status;

	if ((observer == NULL) || (hash == NULL) || (store == NULL)) {
		return PCD_OBSERVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (struct pcd_observer_pcr));

	status = manifest_pcr_init (&observer->pcr, hash, store, manifest_measurement,
		manifest_id_measurement, platform_id_measurement, PCD_OBSERVER_MEASUREMENTS_NOT_UNIQUE);
	if (status != 0) {
		return status;
	}

	observer->base.on_pcd_activated = pcd_observer_pcr_on_pcd_activated;
	observer->base.on_clear_active = pcd_observer_pcr_on_clear_active;

	return 0;
}

/**
 * Release the resources used by the PCD observer.
 *
 * @param observer The observer to release.
 */
void pcd_observer_pcr_release (struct pcd_observer_pcr *observer)
{
	if (observer) {
		manifest_pcr_release (&observer->pcr);
	}
}

/**
 * Force the PCR to be updated with the current active PCD measurement.
 *
 * @param observer The observer for the PCR to update.
 * @param manager The manager for the PCD measurement to update.
 */
void pcd_observer_pcr_record_measurement (struct pcd_observer_pcr *observer,
	struct pcd_manager *manager)
{
	struct pcd *active;
	struct pcd_observer_pcr *pcr = (struct pcd_observer_pcr*) observer;

	if ((observer == NULL) || (manager == NULL)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_PCD_RECORD_INVALID, PCD_OBSERVER_INVALID_ARGUMENT, 0);
		return;
	}

	active = manager->get_active_pcd (manager);
	if (active) {
		manifest_pcr_record_manifest_measurement (&pcr->pcr, &active->base);
		manager->free_pcd (manager, active);
	}
	else {
		manifest_pcr_record_manifest_measurement (&pcr->pcr, NULL);
	}
}
