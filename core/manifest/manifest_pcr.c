// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_pcr.h"
#include "manifest_logging.h"


/**
 * Initialize common manifest PCR management.  This is only intended to be initialized as part of
 * a parent module.  No null checking will be done on the input parameters.
 *
 * @param pcr The PCR management to initialize.
 * @param hash The hash engine to use for generating PCR measurements.
 * @param store The PCR store to update as the CFM changes.
 * @param measurement_type The identifier for the measurement in the PCR.
 *
 * @return 0 if the PCR manager was successfully initialized or an error code.
 */
int manifest_pcr_init (struct manifest_pcr *pcr, struct hash_engine *hash,
	struct pcr_store *store, uint16_t measurement_type)
{
	int status;

	status = pcr_store_check_measurement_type (store, measurement_type);
	if (status != 0) {
		return status;
	}

	pcr->hash = hash;
	pcr->store = store;
	pcr->measurement_id = measurement_type;

	return 0;
}

/**
 * Release the resources used for manifest PCR management.
 *
 * @param pcr The PCR manager to release.
 */
void manifest_pcr_release (struct manifest_pcr *pcr)
{

}

/**
 * Record the measurement for the provide manifest.
 *
 * @param pcr The PCR manager that will record the measurement.
 * @param active The manifest to measure.
 */
void manifest_pcr_record_manifest_measurement (struct manifest_pcr *pcr, struct manifest *active)
{
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	status = active->get_hash (active, pcr->hash, measurement, sizeof (measurement));
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_GET_MEASUREMENT_FAIL, pcr->measurement_id, status);
		return;
	}

	status = pcr_store_update_digest (pcr->store, pcr->measurement_id, measurement,
		SHA256_HASH_LENGTH);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, pcr->measurement_id, status);
	}
}
