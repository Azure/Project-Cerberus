// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "manifest_logging.h"
#include "manifest_pcr.h"
#include "platform_api.h"
#include "common/unused.h"


/**
 * Initialize common manifest PCR management.  This is only intended to be initialized as part of
 * a parent module.  No null checking will be done on the input parameters.
 *
 * @param pcr The PCR management to initialize.
 * @param hash The hash engine to use for generating manifest measurements.
 * @param store The PCR store to update as the manifest changes.
 * @param manifest_measurement The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement The identifier for the manifest ID measurement in the PCR.
 * @param manifest_platform_id_measurement The identifier for the manifest platform ID measurement
 * in the PCR.
 * @param error The error code to return if measurements are not unique.
 *
 * @return 0 if the PCR manager was successfully initialized or an error code.
 */
int manifest_pcr_init (struct manifest_pcr *pcr, const struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t manifest_platform_id_measurement, int not_unique)
{
	pcr->hash = hash;
	pcr->store = store;
	pcr->manifest_measurement = manifest_measurement;
	pcr->manifest_id_measurement = manifest_id_measurement;
	pcr->manifest_platform_id_measurement = manifest_platform_id_measurement;

	return manifest_pcr_check_measurements (pcr, -1, not_unique);
}

/**
 * Release the resources used for manifest PCR management.
 *
 * @param pcr The PCR manager to release.
 */
void manifest_pcr_release (const struct manifest_pcr *pcr)
{
	UNUSED (pcr);
}

/**
 * Check that the configured measurements for the manifest are valid.  This will also check that the
 * PCR manager was properly initialized.
 *
 * @param pcr The PCR manager to check.
 * @param invalid_arg The error code to return for a null pointer.
 * @param not_unique The error code to return if measurements are not unique.
 *
 * @return 0 if the measurements are all valid or an error code.
 */
int manifest_pcr_check_measurements (const struct manifest_pcr *pcr, int invalid_arg,
	int not_unique)
{
	int status;

	if ((pcr == NULL) || (pcr->hash == NULL) || (pcr->store == NULL)) {
		return invalid_arg;
	}

	if ((pcr->manifest_measurement == pcr->manifest_id_measurement) ||
		(pcr->manifest_measurement == pcr->manifest_platform_id_measurement) ||
		(pcr->manifest_id_measurement == pcr->manifest_platform_id_measurement)) {
		return not_unique;
	}

	status = pcr_store_check_measurement_type (pcr->store, pcr->manifest_measurement);
	if (status != 0) {
		return status;
	}

	status = pcr_store_check_measurement_type (pcr->store, pcr->manifest_id_measurement);
	if (status != 0) {
		return status;
	}

	status = pcr_store_check_measurement_type (pcr->store, pcr->manifest_platform_id_measurement);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Record all measurements for the provided manifest.  Errors generating manifest measurements
 * will be logged and will prevent updates to subsequent measurements.
 *
 * @param pcr The PCR manager that will record the measurement.
 * @param active The manifest to measure.
 *
 * @return 0 if the manifest was measured successfully or an error code.
 */
int manifest_pcr_record_manifest_measurement (const struct manifest_pcr *pcr,
	const struct manifest *active)
{
	return manifest_pcr_measure_manifest (active, pcr->hash, pcr->store, pcr->manifest_measurement,
		pcr->manifest_id_measurement, pcr->manifest_platform_id_measurement);
}

/**
 * Measure a manifest into the specified measurement IDs.  Errors generating manifest measurements
 * will be logged and will prevent updates to subsequent measurements.
 *
 * This has the same behavior as manifest_pcr_record_manifest_measurement but can be called from
 * contexts that do not have a manifest_pcr instance.
 *
 * @param active The manifest to measure.
 * @param hash The hash engine to use for generating manifest measurements.
 * @param store The PCR store to update with manifest measurements.
 * @param manifest_measurement The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement The identifier for the manifest ID measurement in the PCR.
 * @param manifest_platform_id_measurement The identifier for the manifest platform ID measurement
 * in the PCR.
 *
 * @return 0 if the manifest was measured successfully or an error code.
 */
int manifest_pcr_measure_manifest (const struct manifest *active, const struct hash_engine *hash,
	struct pcr_store *store, uint16_t manifest_measurement, uint16_t manifest_id_measurement,
	uint16_t manifest_platform_id_measurement)
{
	uint8_t manifest_digest[HASH_MAX_HASH_LEN] = {0};
	int digest_length = SHA256_HASH_LENGTH;
	uint8_t id[5];
	char *platform_id = NULL;
	char empty_string = '\0';
	int status;

	if (active) {
		digest_length = active->get_hash (active, hash, manifest_digest, sizeof (manifest_digest));
		if (ROT_IS_ERROR (digest_length)) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_GET_MEASUREMENT_FAIL, manifest_measurement, digest_length);

			return digest_length;
		}
	}

	status = pcr_store_update_versioned_buffer (store, hash, manifest_measurement, manifest_digest,
		digest_length, true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, manifest_measurement, status);

		return status;
	}

	if (active == NULL) {
		memset (id, 0, sizeof (id));
	}
	else {
		id[0] = 1;
		status = active->get_id (active, (uint32_t*) &id[1]);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_GET_ID_FAIL, manifest_id_measurement, status);

			return status;
		}
	}

	status = pcr_store_update_versioned_buffer (store, hash, manifest_id_measurement, id,
		sizeof (id), true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, manifest_id_measurement, status);

		return status;
	}

	if (active == NULL) {
		platform_id = &empty_string;
	}
	else {
		status = active->get_platform_id (active, &platform_id, 0);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_GET_PLATFORM_ID_FAIL, manifest_platform_id_measurement, status);

			return status;
		}
	}

	status = pcr_store_update_versioned_buffer (store, hash, manifest_platform_id_measurement,
		(uint8_t*) platform_id, strlen (platform_id) + 1, true, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_RECORD_MEASUREMENT_FAIL, manifest_platform_id_measurement, status);
	}

	if (active != NULL) {
		active->free_platform_id (active, platform_id);
	}

	return status;
}
