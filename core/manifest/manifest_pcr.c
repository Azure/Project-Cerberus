// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "manifest_pcr.h"
#include "manifest_logging.h"


/**
 * Initialize common manifest PCR management.  This is only intended to be initialized as part of
 * a parent module.  No null checking will be done on the input parameters.
 *
 * @param pcr The PCR management to initialize.
 * @param hash The hash engine to use for generating PCR measurements.
 * @param store The PCR store to update as the CFM changes.
 * @param manifest_measurement The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement The identifier for the manifest ID measurement in the PCR.
 * @param manifest_platform_id_measurement The identifier for the manifest platform ID measurement
 * in the PCR.
 * @param error The error code to return if measurements are not unique
 *
 * @return 0 if the PCR manager was successfully initialized or an error code.
 */
int manifest_pcr_init (struct manifest_pcr *pcr, struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t manifest_platform_id_measurement, int error)
{
	int status;

	if ((manifest_measurement == manifest_id_measurement) ||
		(manifest_measurement == manifest_platform_id_measurement) ||
		(manifest_id_measurement == manifest_platform_id_measurement)) {
		return error;
	}

	status = pcr_store_check_measurement_type (store, manifest_measurement);
	if (status != 0) {
		return status;
	}

	status = pcr_store_check_measurement_type (store, manifest_id_measurement);
	if (status != 0) {
		return status;
	}

	status = pcr_store_check_measurement_type (store, manifest_platform_id_measurement);
	if (status != 0) {
		return status;
	}

	pcr->hash = hash;
	pcr->store = store;
	pcr->manifest_measurement = manifest_measurement;
	pcr->manifest_id_measurement = manifest_id_measurement;
	pcr->manifest_platform_id_measurement = manifest_platform_id_measurement;

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
 * Record the measurement for the provided manifest.
 *
 * @param pcr The PCR manager that will record the measurement.
 * @param active The manifest to measure.
 */
void manifest_pcr_record_manifest_measurement (struct manifest_pcr *pcr, struct manifest *active)
{
	uint8_t manifest_measurement[SHA256_HASH_LENGTH];
	uint8_t id[5];
	char *platform_id = NULL;
	char empty_string = '\0';
	int status;

	if (active == NULL) {
		status = pcr->hash->calculate_sha256 (pcr->hash, NULL, 0, manifest_measurement,
			sizeof (manifest_measurement));
	}
	else {
		status = active->get_hash (active, pcr->hash, manifest_measurement,
			sizeof (manifest_measurement));
	}

	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_GET_MEASUREMENT_FAIL, pcr->manifest_measurement, status);
		return;
	}
	
	status = pcr_store_update_digest (pcr->store, pcr->manifest_measurement, manifest_measurement,
		SHA256_HASH_LENGTH);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, pcr->manifest_measurement, status);
		return;
	}

	if (active == NULL) {
		memset (id, 0, sizeof (id));
	}
	else {
		id[0] = 1;
		status = active->get_id (active, (uint32_t*) &id[1]);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_GET_ID_FAIL, pcr->manifest_id_measurement, status);
			return;
		}
	}

	status = pcr_store_update_buffer (pcr->store, pcr->hash, pcr->manifest_id_measurement, id,
		sizeof (id), true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, pcr->manifest_id_measurement, status);
		return;
	}

	if (active == NULL) {
		platform_id = &empty_string;
	}
	else {
		status = active->get_platform_id (active, &platform_id);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_GET_PLATFORM_ID_FAIL, pcr->manifest_platform_id_measurement, status);
			return;
		}
	}

	status = pcr_store_update_buffer (pcr->store, pcr->hash, pcr->manifest_platform_id_measurement,
		(uint8_t*) platform_id, strlen (platform_id) + 1, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, pcr->manifest_platform_id_measurement, status);
	}

	if (active != NULL) {
		platform_free (platform_id);
	}
}
