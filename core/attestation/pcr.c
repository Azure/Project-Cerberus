// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "platform.h"
#include "pcr.h"


/**
 * Initialize PCR bank to support the required number of measurements
 *
 * @param pcr The PCR bank to initialize
 * @param pcr_num_measurements The number of measurements to initialize the PCR bank to hold.  If
 * this is set to 0, the bank will hold a single measurement that will be treated as an explicit
 * measurement.  An explicit measurement will not be hashed when computing the bank PCR.
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_init (struct pcr_bank *pcr, uint8_t pcr_num_measurements)
{
	int status;

	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	memset (pcr, 0, sizeof (struct pcr_bank));

	status = platform_mutex_init (&pcr->lock);
	if (status != 0) {
		return status;
	}

	if (pcr_num_measurements == 0) {
		pcr_num_measurements = 1;
		pcr->explicit = true;
	}

	pcr->measurement_list = platform_calloc (pcr_num_measurements, sizeof (struct pcr_measurement));
	if (pcr->measurement_list == NULL) {
		platform_mutex_free (&pcr->lock);
		return PCR_NO_MEMORY;
	}

	pcr->num_measurements = pcr_num_measurements;

	return 0;
}

/**
 * Release resources held by the PCR bank
 *
 * @param pcr The PCR bank to release
 */
void pcr_release (struct pcr_bank *pcr)
{
	if (pcr != NULL) {
		platform_mutex_free (&pcr->lock);
		platform_free (pcr->measurement_list);
		pcr->num_measurements = 0;
	}
}

/**
 * Indicate if the measurement index is valid for the PCR.
 *
 * @param pcr The PCR bank to query.
 * @param measurement_index The measurement index to check.
 *
 * @return 0 if the measurement index is valid or an error code.
 */
int pcr_check_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	return 0;
}

/**
 * Update digest in PCR bank's list of measurements
 *
 * @param pcr PCR bank to update
 * @param measurement_index The index of measurement being updated
 * @param digest Buffer holding digest to add
 * @param digest_len Length of digest buffer
 *
 * @return 0 if successful or an error code
 */
int pcr_update_digest (struct pcr_bank *pcr, uint8_t measurement_index, const uint8_t *digest,
	size_t digest_len)
{
	if ((pcr == NULL) || (digest == NULL) || (digest_len == 0)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (digest_len != PCR_DIGEST_LENGTH) {
		return PCR_UNSUPPORTED_ALGO;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	memcpy (pcr->measurement_list[measurement_index].digest, digest, digest_len);

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Compute digest of buffer and update the PCR bank's list of measurements
 *
 * @param pcr PCR bank to update measurement in
 * @param hash Hashing engine to utilize
 * @param measurement_index The index of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_update_buffer (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t measurement_index,
	const uint8_t *buf, size_t buf_len)
{
	uint8_t digest[PCR_DIGEST_LENGTH];
	int status;

	if ((pcr == NULL) || (buf == NULL) || (buf_len == 0) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	status = hash->calculate_sha256 (hash, buf, buf_len, digest, sizeof (digest));
	if (status != 0) {
		return status;
	}

	return pcr_update_digest (pcr, measurement_index, digest, sizeof (digest));
}

/**
 * Compute aggregate of all measurements that have added to PCR bank
 *
 * @param pcr The PCR bank to compute aggregate measurement of
 * @param hash Hashing engine to utilize
 * @param measurement Optional output buffer to return back PCR measurement
 * @param lock Boolean indicating whether mutex should be acquired during computation or not
 *
 * @return Number of measurements aggregated or an error code
 */
int pcr_compute (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t *measurement, bool lock)
{
	uint8_t prev_measurement[PCR_DIGEST_LENGTH] = {0};
	int i_measurement;
	int status = 0;

	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (lock) {
		platform_mutex_lock (&pcr->lock);
	}

	if (!pcr->explicit) {
		for (i_measurement = 0; i_measurement < pcr->num_measurements; ++i_measurement) {
			status = hash->start_sha256 (hash);
			if (status != 0) {
				goto exit;
			}

			status = hash->update (hash, prev_measurement, sizeof (prev_measurement));
			if (status != 0) {
				goto hash_cancel;
			}

			status = hash->update (hash, pcr->measurement_list[i_measurement].digest,
				sizeof (pcr->measurement_list[i_measurement].digest));
			if (status != 0) {
				goto hash_cancel;
			}

			status = hash->finish (hash, prev_measurement, sizeof (prev_measurement));
			if (status != 0) {
				goto hash_cancel;
			}

			memcpy (pcr->measurement_list[i_measurement].measurement, prev_measurement,
				sizeof (prev_measurement));
		}
	}
	else {
		memcpy (prev_measurement, pcr->measurement_list[0].digest, sizeof (prev_measurement));
	}

	if (measurement != NULL) {
		memcpy (measurement, prev_measurement, sizeof (prev_measurement));
	}

	if (lock) {
		platform_mutex_unlock (&pcr->lock);
	}

	if (pcr->explicit) {
		return 1;
	}

	return pcr->num_measurements;

hash_cancel:
	hash->cancel (hash);

exit:
	if (lock) {
		platform_mutex_unlock (&pcr->lock);
	}

	return status;
}

/**
 * Retrieve measurement from PCR bank
 *
 * @param pcr The PCR bank to get measurement from
 * @param measurement_index Index of measurement to get back
 * @param measurement Output buffer to return back PCR measurement
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_get_measurement (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measurement *measurement)
{
	if ((pcr == NULL) || (measurement == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	memcpy (measurement, &pcr->measurement_list[measurement_index],
		sizeof (struct pcr_measurement));

	return 0;
}

/**
 * Retrieve all PCR bank measurements
 *
 * @param pcr The PCR bank to get measurements from
 * @param measurement_list Buffer to hold pointer to PCR measurements.
 *
 * @return Number of measurements in list or an error code
 */
int pcr_get_all_measurements (struct pcr_bank *pcr, const uint8_t **measurement_list)
{
	if ((pcr == NULL) || (measurement_list == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	*measurement_list = (uint8_t*) pcr->measurement_list;

	return pcr->num_measurements;
}

/**
 * Retrieve number of measurements in PCR bank
 *
 * @param pcr The PCR bank to get number of measurements from
 *
 * @return Number of measurements in PCR bank or an error code
 */
int pcr_get_num_measurements (struct pcr_bank *pcr)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr->explicit) {
		return 0;
	}

	return pcr->num_measurements;
}

/**
 * Invalidate a measurement in the PCR bank 
 *
 * @param pcr PCR bank to update
 * @param measurement_index The index of measurement being invalidated
 *
 * @return 0 if successful or an error code
 */
int pcr_invalidate_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	memset (pcr->measurement_list[measurement_index].digest, 0, 
		sizeof (pcr->measurement_list[measurement_index].digest));

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Acquire lock dedicated to PCR bank
 *
 * @param pcr The PCR bank to lock
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_lock (struct pcr_bank *pcr)
{
	if (pcr) {
		return platform_mutex_lock (&pcr->lock);
	}
	else {
		return PCR_INVALID_ARGUMENT;
	}
}

/**
 * Release lock dedicated to PCR bank
 *
 * @param pcr The PCR bank to unlock
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_unlock (struct pcr_bank *pcr)
{
	if (pcr) {
		return platform_mutex_unlock (&pcr->lock);
	}
	else {
		return PCR_INVALID_ARGUMENT;
	}
}
