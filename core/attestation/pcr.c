// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "pcr.h"
#include "platform_api.h"
#include "common/common_math.h"
#include "flash/flash.h"
#include "flash/flash_util.h"


/**
 * Initialize a PCR with support for a fixed number of measurements.  Memory for managing the state
 * of each measurement will be dynamically allocated.
 *
 * @param pcr The PCR to initialize.
 * @param config The configuration for the PCR.  If the PCR is configured to hold no measurements,
 * it will hold a single measurement that will be treated as an explict PCR value, meaning it will
 * be directly returned when computing the PCR without any additional operations performed.
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_init (struct pcr_bank *pcr, const struct pcr_config *config)
{
	size_t num_measurements;
	int status;

	if ((pcr == NULL) || (config == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	status = hash_get_hash_length (config->measurement_algo);
	if (status == HASH_ENGINE_UNKNOWN_HASH) {
		return PCR_UNSUPPORTED_ALGO;
	}

	if (!hash_is_alg_supported (config->measurement_algo) || (status > PCR_MAX_DIGEST_LENGTH)) {
		return PCR_UNSUPPORTED_ALGO;
	}

	/* Never support SHA-1 digests. */
	if (config->measurement_algo == HASH_TYPE_SHA1) {
		return PCR_UNSUPPORTED_ALGO;
	}

	memset (pcr, 0, sizeof (struct pcr_bank));

	status = platform_mutex_init (&pcr->lock);
	if (status != 0) {
		return status;
	}

	num_measurements = config->num_measurements;
	if (num_measurements == 0) {
		num_measurements = 1;
		pcr->explicit_measurement = true;
	}

	pcr->measurement_list = platform_calloc (num_measurements, sizeof (struct pcr_measurement));
	if (pcr->measurement_list == NULL) {
		platform_mutex_free (&pcr->lock);

		return PCR_NO_MEMORY;
	}

	pcr->config.num_measurements = num_measurements;
	pcr->config.measurement_algo = config->measurement_algo;

	return 0;
}

/**
 * Release resources held by the PCR.
 *
 * @param pcr The PCR to release.
 */
void pcr_release (struct pcr_bank *pcr)
{
	if (pcr != NULL) {
		platform_mutex_free (&pcr->lock);
		platform_free (pcr->measurement_list);
	}
}

/**
 * Retrieve number of measurements in the PCR.  An explicit PCR value will report has having no
 * measurements.
 *
 * @param pcr The PCR to query.
 *
 * @return Number of measurements in PCR or an error code.
 */
int pcr_get_num_measurements (struct pcr_bank *pcr)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr->explicit_measurement) {
		return 0;
	}

	return pcr->config.num_measurements;
}

/**
 * Indicate if the measurement index is valid for the PCR.
 *
 * @param pcr The PCR to query.
 * @param measurement_index The measurement index to check.
 *
 * @return 0 if the measurement index is valid or an error code.
 */
int pcr_check_measurement_index (struct pcr_bank *pcr, uint8_t measurement_index)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	return 0;
}

/**
 * Retrieve the hash algorithm used to generate measurements for the PCR.
 *
 * @param pcr The PCR to query.
 *
 * @return The hash algorithm used for the PCR.  This will be HASH_TYPE_INVALID if the PCR is null.
 */
enum hash_type pcr_get_hash_algorithm (struct pcr_bank *pcr)
{
	if (pcr == NULL) {
		return HASH_TYPE_INVALID;
	}

	return pcr->config.measurement_algo;
}

/**
 * Retrieve the digest length used for measurements for the PCR.
 *
 * @param pcr The PCR to query.
 *
 * @return Length of PCRs digests or an error code.
 */
int pcr_get_digest_length (struct pcr_bank *pcr)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	return hash_get_hash_length (pcr->config.measurement_algo);
}

/**
 * Set the TCG event type for a measurement in the PCR.
 *
 * @param pcr PCR containing the measurement to update.
 * @param measurement_index The index of the measurement being updated.
 * @param event_type Event type to associate with measurement.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_set_tcg_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t event_type)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	pcr->measurement_list[measurement_index].event_type = event_type;

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Get the TCG event type for a measurement in the PCR.
 *
 * @param pcr PCR containing the measurement to query.
 * @param measurement_index The index of the measurement being accessed.
 * @param event_type Output buffer to store the event type.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_get_tcg_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t *event_type)
{
	if ((pcr == NULL) || (event_type == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	*event_type = pcr->measurement_list[measurement_index].event_type;

	return 0;
}

/**
 * Set the DMTF value type identifier for a measurement in the PCR.
 *
 * @param pcr PCR containing the measurement to update.
 * @param measurement_index The index of the measurement being updated.
 * @param value_type DMTF value type to associate with the measurement.
 * @param is_not_tcb Flag to indicate that a measurement should not be considered part of the TCB
 * when responding to SPDM requests.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_set_dmtf_value_type (struct pcr_bank *pcr, uint8_t measurement_index,
	enum pcr_dmtf_value_type value_type, bool is_not_tcb)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	if (value_type >= PCR_DMTF_VALUE_TYPE_UNUSED) {
		return PCR_INVALID_VALUE_TYPE;
	}

	platform_mutex_lock (&pcr->lock);

	pcr->measurement_list[measurement_index].dmtf_type = value_type;
	pcr->measurement_list[measurement_index].spdm_not_tcb = is_not_tcb;

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Get the DMTF value type identifier for a measurement in the PCR.
 *
 * @param pcr PCR containing the measurement to query.
 * @param measurement_index The index of the measurement being queried.
 * @param value_type Output buffer for the DMTF value type.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_get_dmtf_value_type (struct pcr_bank *pcr, uint8_t measurement_index,
	enum pcr_dmtf_value_type *value_type)
{
	if ((pcr == NULL) || (value_type == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	*value_type = pcr->measurement_list[measurement_index].dmtf_type;

	return 0;
}

/**
 * Determine if a measurement is part of the Trusted Computing Base (TCB) for the device.
 *
 * @param pcr PCR containing the measurement to query.
 * @param measurement_index The index of the measurement being queried.
 *
 * @return 1 if the measurement is part of the TCB, 0 if not, or an error code.
 */
int pcr_is_measurement_in_tcb (struct pcr_bank *pcr, uint8_t measurement_index)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	return !pcr->measurement_list[measurement_index].spdm_not_tcb;
}

/**
 * Update the current digest for a single measurement.
 *
 * @param pcr PCR containing the measurement to update.
 * @param measurement_index The index of measurement being updated.
 * @param digest The digest that should be stored in the measurement.
 * @param digest_len Length of digest.  This must match exactly the digest length for the PCR.
 * @param measurement_config Indicates what data included as part of the digest calculation.
 * @param version Optional version number that was include as part of the digest.
 *
 * @return 0 if successful or an error code.
 */
static int pcr_update_digest_common (struct pcr_bank *pcr, uint8_t measurement_index,
	const uint8_t *digest, size_t digest_len, uint8_t measurement_config, uint8_t version)
{
	bool is_constant;
	int status = 0;

	if ((pcr == NULL) || (digest == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (digest_len != (size_t) hash_get_hash_length (pcr->config.measurement_algo)) {
		return PCR_INCORRECT_DIGEST_LENGTH;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	is_constant = !!(pcr->measurement_list[measurement_index].measurement_config &
		PCR_MEASUREMENT_FLAG_CONSTANT);

	if (!is_constant) {
		memcpy (pcr->measurement_list[measurement_index].digest, digest, digest_len);
		pcr->measurement_list[measurement_index].measurement_config = measurement_config;
		pcr->measurement_list[measurement_index].version = version;
	}
	else {
		status = PCR_CONSTANT_MEASUREMENT;
	}

	platform_mutex_unlock (&pcr->lock);

	return status;
}

/**
 * Store a pre-computed digest for a measurement in the PCR.
 *
 * @param pcr PCR containing the measurement to update.
 * @param measurement_index The index of measurement being updated.
 * @param digest The digest data that should be stored for the measurement.
 * @param digest_len Length of digest.  This must match exactly the digest length for the PCR.
 *
 * @return 0 if successful or an error code.
 */
int pcr_update_digest (struct pcr_bank *pcr, uint8_t measurement_index, const uint8_t *digest,
	size_t digest_len)
{
	return pcr_update_digest_common (pcr, measurement_index, digest, digest_len, 0, 0);
}

/**
 * Update a specified measurement in a PCR by computing the digest of a data buffer.  Event type
 * and/or version details can be prepended to the data during the calculation.
 *
 * @param PCR containing the measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_index The index of the measurement being updated.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations.
 * @param include_version Flag that indicates whether to include the version in measurement
 * calculations.
 * @param is_constant Flag that indicates whether the measurement should prevent future updates.
 * @param version The version associated with the measurement data.
 *
 * @return Completion status, 0 if success or an error code
 */
static int pcr_update_buffer_common (struct pcr_bank *pcr, const struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	bool include_version, bool is_constant, uint8_t version)
{
	uint8_t digest[PCR_MAX_DIGEST_LENGTH];
	uint8_t config = 0;
	int status;

	/* If there is an attempt to update buffer with 0 total bytes, using no data buffer and not
	 * including event and version information, then fail due to invalid arguments */
	if (!include_event && !include_version && ((buf == NULL) || (buf_len == 0))) {
		return PCR_INVALID_ARGUMENT;
	}

	status = hash_start_new_hash (hash, pcr->config.measurement_algo);
	if (status != 0) {
		return status;
	}

	if (include_event) {
		status = hash->update (hash,
			(uint8_t*) &pcr->measurement_list[measurement_index].event_type,
			sizeof (pcr->measurement_list[measurement_index].event_type));
		if (status != 0) {
			goto hash_cancel;
		}

		config |= PCR_MEASUREMENT_FLAG_EVENT;
	}

	if (include_version) {
		status = hash->update (hash, &version, sizeof (version));
		if (status != 0) {
			goto hash_cancel;
		}

		config |= PCR_MEASUREMENT_FLAG_VERSION;
	}
	else {
		version = 0;
	}

	if (is_constant) {
		config |= PCR_MEASUREMENT_FLAG_CONSTANT;
	}

	status = hash->update (hash, buf, buf_len);
	if (status != 0) {
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		goto hash_cancel;
	}

	return pcr_update_digest_common (pcr, measurement_index, digest,
		hash_get_hash_length (pcr->config.measurement_algo), config, version);

hash_cancel:
	hash->cancel (hash);

	return status;
}

/**
 * Update a specified measurement in a PCR by computing the digest of a data buffer.
 *
 * @param pcr PCR containing the measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_index The index of the measurement being updated.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_update_buffer (struct pcr_bank *pcr, const struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event)
{
	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len, include_event,
		false, false, 0);
}

/**
 * Update a specified measurement in a PCR by computing the digest of a versioned data buffer.
 *
 * @param pcr PCR containing the measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_index The index of the measurement being updated.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param version The version associated with the measurement data, which will prepended when
 * calculating the digest.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_update_versioned_buffer (struct pcr_bank *pcr, const struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version)
{
	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len, include_event,
		true, false, version);
}

/**
 * Store a pre-computed digest for a measurement in the PCR.  The measurement will be locked from
 * any future modification.
 *
 * @param pcr PCR containing the measurement to update.
 * @param measurement_index The index of measurement being updated.
 * @param digest The digest data that should be stored for the measurement.
 * @param digest_len Length of digest.  This must match exactly the digest length for the PCR.
 *
 * @return 0 if successful or an error code.
 */
int pcr_const_update_digest (struct pcr_bank *pcr, uint8_t measurement_index, const uint8_t *digest,
	size_t digest_len)
{
	return pcr_update_digest_common (pcr, measurement_index, digest, digest_len,
		PCR_MEASUREMENT_FLAG_CONSTANT, 0);
}

/**
 * Update a specified measurement in a PCR by computing the digest of a data buffer.  The
 * measurement will be locked from any future modification.
 *
 * @param pcr PCR containing the measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_index The index of the measurement being updated.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_const_update_buffer (struct pcr_bank *pcr, const struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event)
{
	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len, include_event,
		false, true, 0);
}

/**
 * Update a specified measurement in a PCR by computing the digest of a versioned data buffer.  The
 * measurement will be locked from any future modification.
 *
 * @param pcr PCR containing the measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_index The index of the measurement being updated.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param version The version associated with the measurement data, which will prepended when
 * calculating the digest.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_const_update_versioned_buffer (struct pcr_bank *pcr, const struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version)
{
	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len, include_event,
		true, true, version);
}

/**
 * Clear the currently stored digest for a measurement in the PCR.
 *
 * @param pcr The PCR containing the measurement to clear.
 * @param measurement_index The index of measurement being cleared.
 *
 * @return 0 if successful or an error code.
 */
int pcr_invalidate_measurement (struct pcr_bank *pcr, uint8_t measurement_index)
{
	bool is_constant;
	int status = 0;

	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	is_constant = !!(pcr->measurement_list[measurement_index].measurement_config &
		PCR_MEASUREMENT_FLAG_CONSTANT);

	if (!is_constant) {
		memset (pcr->measurement_list[measurement_index].digest, 0,
			sizeof (pcr->measurement_list[measurement_index].digest));
	}
	else {
		status = PCR_CONSTANT_MEASUREMENT;
	}

	platform_mutex_unlock (&pcr->lock);

	return status;
}

/**
 * Compute the PCR value based on the current state of the measurements.  All measurements will be
 * included in the PCR calculation, even if they have not been updated with a value or if they have
 * been invalidated.
 *
 * @param pcr The PCR to calculate.
 * @param hash Hashing engine to use for the calculation.
 * @param lock true to acquire the PCR mutex during the calculation.  If this is false, it is
 * expected that the lock is managed externally.
 * @param measurement Optional output buffer to return the PCR value.  Setting this to null will
 * still refresh the measurement state.
 * @param length Size of the measurement output buffer.
 *
 * @return Length of the generated PCR value or an error code.  Use ROT_IS_ERROR to check the return
 * status.
 */
int pcr_compute (struct pcr_bank *pcr, const struct hash_engine *hash, bool lock,
	uint8_t *measurement, size_t length)
{
	uint8_t prev_measurement[PCR_MAX_DIGEST_LENGTH] = {0};
	int hash_length;
	size_t i;
	int status = 0;

	if ((pcr == NULL) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	hash_length = hash_get_hash_length (pcr->config.measurement_algo);

	if ((measurement != NULL) && (length < (size_t) hash_length)) {
		return PCR_SMALL_OUTPUT_BUFFER;
	}

	if (lock) {
		platform_mutex_lock (&pcr->lock);
	}

	if (!pcr->explicit_measurement) {
		for (i = 0; i < pcr->config.num_measurements; ++i) {
			status = hash_start_new_hash (hash, pcr->config.measurement_algo);
			if (status != 0) {
				goto exit;
			}

			status = hash->update (hash, prev_measurement, hash_length);
			if (status != 0) {
				goto hash_cancel;
			}

			status = hash->update (hash, pcr->measurement_list[i].digest, hash_length);
			if (status != 0) {
				goto hash_cancel;
			}

			status = hash->finish (hash, prev_measurement, sizeof (prev_measurement));
			if (status != 0) {
				goto hash_cancel;
			}

			memcpy (pcr->measurement_list[i].measurement, prev_measurement,
				sizeof (prev_measurement));
		}

		if (measurement != NULL) {
			memcpy (measurement, prev_measurement, hash_length);
		}
	}
	else if (measurement != NULL) {
		memcpy (measurement, pcr->measurement_list[0].digest, hash_length);
	}

	status = hash_length;
	goto exit;

hash_cancel:
	hash->cancel (hash);

exit:
	if (lock) {
		platform_mutex_unlock (&pcr->lock);
	}

	return status;
}

/**
 * Retrieve details for a single measurement in a PCR.
 *
 * @param pcr The PCR containing the requested measurement.
 * @param measurement_index Index of measurement to get.
 * @param measurement Output buffer to return measurement.
 *
 * @return Length of the measurement digest or an error code.  Use ROT_IS_ERROR to check the return
 * status.
 */
int pcr_get_measurement (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measurement *measurement)
{
	if ((pcr == NULL) || (measurement == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	memcpy (measurement, &pcr->measurement_list[measurement_index],
		sizeof (struct pcr_measurement));

	return hash_get_hash_length (pcr->config.measurement_algo);
}

/**
 * Retrieve a list of all measurements for the PCR.
 *
 * @param pcr The PCR containing the requested measurements.
 * @param measurement_list Output to for the list of PCR measurements.
 *
 * @return The digest length used for all measurements or an error code.  Use ROT_IS_ERROR to check
 * the return status.
 */
int pcr_get_all_measurements (struct pcr_bank *pcr,	const struct pcr_measurement **measurement_list)
{
	if ((pcr == NULL) || (measurement_list == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	*measurement_list = pcr->measurement_list;

	return hash_get_hash_length (pcr->config.measurement_algo);
}

/**
 * Indicate if a measurement has access to the raw data that was measured.
 *
 * @param pcr The PCR containing the measurement to query.
 * @param measurement_index Index of the measurement to query.
 *
 * @return 1 if the measurement has access to the raw data, 0 if not, or an error code.
 */
int pcr_is_measurement_data_available (struct pcr_bank *pcr, uint8_t measurement_index)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	return (pcr->measurement_list[measurement_index].measured_data == NULL) ? 0 : 1;
}

/**
 * Set the raw data that is measured for a single measurement in the PCR.
 *
 * @param pcr The PCR containing the measurement to update.
 * @param measurement_index Index of measurement to set.
 * @param measurement_data Descriptor for the raw data associated with the measurement.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_set_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	const struct pcr_measured_data *measurement_data)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	if (measurement_data != NULL) {
		switch (measurement_data->type) {
			case PCR_DATA_TYPE_1BYTE:
			case PCR_DATA_TYPE_2BYTE:
			case PCR_DATA_TYPE_4BYTE:
			case PCR_DATA_TYPE_8BYTE:
			case PCR_DATA_TYPE_MEMORY:
				break;

			case PCR_DATA_TYPE_FLASH:
				if (measurement_data->data.flash.flash == NULL) {
					return PCR_MEASURED_DATA_INVALID_FLASH_DEVICE;
				}
				break;

			case PCR_DATA_TYPE_CALLBACK:
				if (measurement_data->data.callback.get_data == NULL) {
					return PCR_MEASURED_DATA_INVALID_CALLBACK;
				}
				break;

			default:
				return PCR_INVALID_DATA_TYPE;
		}
	}

	platform_mutex_lock (&pcr->lock);

	pcr->measurement_list[measurement_index].measured_data = measurement_data;

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Copy measurement data bytes into a destination buffer.  Only bytes that fit into the destination
 * buffer will be copied.
 *
 * @param data Buffer storing the measurement data to be read.
 * @param data_len Size in bytes of the measurement data.
 * @param offset The offset index to start reading from.
 * @param buffer Output buffer yor the measured data.
 * @param buffer_len Maximum length of the buffer.
 *
 * @return Total number of bytes read.
 */
static int pcr_read_measurement_data_bytes (const uint8_t *data, size_t data_len, size_t offset,
	uint8_t *buffer, size_t buffer_len)
{
	int bytes_read;

	if ((data == NULL) || (data_len == 0) || (buffer_len == 0) || (offset > (data_len - 1))) {
		return 0;
	}

	/* TODO: Can this be done with buffer_copy? */
	bytes_read = ((data_len - offset) > buffer_len) ? buffer_len : (data_len - offset);
	memcpy (buffer, data + offset, bytes_read);

	return bytes_read;
}

/**
 * Internal function to retrieve the measured data for a single measurement.
 *
 * No data will be written and no error will be generated if the measurement does not have a
 * registered data descriptor.
 *
 * @param pcr The PCR containing the measurement to query.
 * @param measurement_index Index of the measurement to get.
 * @param offset The offset index to starting reading the data.
 * @param buffer Output buffer for the measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output containing the total length of the measurement data. This will contain
 * the total length of the measured data even if the data is only partially returned.
 *
 * @return Length of the buffer if the measured data was retrieved successfully or an error code.
 */
static int pcr_get_measurement_data_internal (struct pcr_bank *pcr, uint8_t measurement_index,
	size_t offset, uint8_t *buffer, size_t length, size_t *total_len)
{
	const struct pcr_measured_data *measured_data;
	bool include_event;
	bool include_version;
	size_t total_bytes = 0;
	size_t bytes_read;
	uint32_t data_len;
	int status = 0;

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	*total_len = 0;

	measured_data = pcr->measurement_list[measurement_index].measured_data;
	if (measured_data == NULL) {
		return 0;
	}

	include_event = pcr->measurement_list[measurement_index].measurement_config &
		PCR_MEASUREMENT_FLAG_EVENT;
	include_version = pcr->measurement_list[measurement_index].measurement_config &
		PCR_MEASUREMENT_FLAG_VERSION;

	if (include_event) {
		if (offset < 4) {
			bytes_read =
				pcr_read_measurement_data_bytes (
				(uint8_t*) &pcr->measurement_list[measurement_index].event_type, 4, offset, buffer,
				length);
			offset = 0;
			length -= bytes_read;
			buffer = buffer + bytes_read;
			total_bytes += bytes_read;
		}
		else {
			offset -= 4;
		}

		*total_len += 4;
	}

	if (include_version) {
		if (offset < 1) {
			bytes_read =
				pcr_read_measurement_data_bytes (&pcr->measurement_list[measurement_index].version,
				1, offset, buffer, length);
			offset = 0;
			length -= bytes_read;
			buffer = buffer + bytes_read;
			total_bytes += bytes_read;
		}
		else {
			offset -= 1;
		}

		*total_len += 1;
	}

	switch (measured_data->type) {
		case PCR_DATA_TYPE_1BYTE:
			bytes_read = pcr_read_measurement_data_bytes (&measured_data->data.value_1byte, 1,
				offset, buffer, length);
			status = bytes_read + total_bytes;
			*total_len += 1;
			break;

		case PCR_DATA_TYPE_2BYTE:
			bytes_read =
				pcr_read_measurement_data_bytes ((uint8_t*) &measured_data->data.value_2byte, 2,
				offset, buffer, length);
			status = bytes_read + total_bytes;
			*total_len += 2;
			break;

		case PCR_DATA_TYPE_4BYTE:
			bytes_read =
				pcr_read_measurement_data_bytes ((uint8_t*) &measured_data->data.value_4byte, 4,
				offset, buffer, length);
			status = bytes_read + total_bytes;
			*total_len += 4;
			break;

		case PCR_DATA_TYPE_8BYTE:
			bytes_read =
				pcr_read_measurement_data_bytes ((uint8_t*) &measured_data->data.value_8byte, 8,
				offset, buffer, length);
			status = bytes_read + total_bytes;
			*total_len += 8;
			break;

		case PCR_DATA_TYPE_MEMORY:
			bytes_read = pcr_read_measurement_data_bytes (measured_data->data.memory.buffer,
				measured_data->data.memory.length, offset, buffer, length);
			status = bytes_read + total_bytes;
			*total_len += measured_data->data.memory.length;
			break;

		case PCR_DATA_TYPE_FLASH: {
			const struct flash *flash_device = measured_data->data.flash.flash;
			size_t read_addr = measured_data->data.flash.addr + offset;

			if (offset > (measured_data->data.flash.length - 1)) {
				status = total_bytes;
			}
			else {
				bytes_read = (((measured_data->data.flash.length - offset) > length) ? length :
						(measured_data->data.flash.length - offset));

				status = flash_device->read (flash_device, read_addr, buffer, bytes_read);
				if (status == 0) {
					status = bytes_read + total_bytes;
				}
			}

			*total_len += measured_data->data.flash.length;
			break;
		}

		case PCR_DATA_TYPE_CALLBACK:
			status = measured_data->data.callback.get_data (measured_data->data.callback.context,
				offset, buffer, length, &data_len);
			if (!ROT_IS_ERROR (status)) {
				status = status + total_bytes;
			}

			*total_len += data_len;

			break;

		default:
			status = PCR_INVALID_DATA_TYPE;
			break;
	}

	return status;
}

/**
 * Retrieve the raw data that was used to generate a measurement in the PCR.
 *
 * No data will be written and no error will be generated if the measurement has not been provided
 * with access to the raw data.
 *
 * @param pcr The PCR containing the measurement to query.
 * @param measurement_index Index of the measurement to get.
 * @param offset An offset into the measured data to start reading the data from.
 * @param buffer Output buffer for the measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output containing the total length of the measurement data. This will contain
 * the total length of the measured data even if the data is only partially returned.
 *
 * @return The amount of data that was written into the output buffer or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int pcr_get_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index, size_t offset,
	uint8_t *buffer, size_t length, size_t *total_len)
{
	int status;

	if ((pcr == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&pcr->lock);

	status = pcr_get_measurement_data_internal (pcr, measurement_index, offset, buffer, length,
		total_len);

	platform_mutex_unlock (&pcr->lock);

	return status;
}

/**
 * Get the hash of the measurement data for a measurement in the PCR.
 *
 * If the requested hash algorithm matches the one used by the PCR, this will just return the
 * current measurement digest.  If the requested hash algorithm is different, the digest will be
 * calculated from the raw data.
 *
 * @param pcr The PCR containing the measurement to hash.
 * @param measurement_index Index of the measurement to hash.
 * @param hash Hash engine to use for calculating the digest, if necessary.
 * @param hash_type The hash algorithm that should be used for digest calculation.
 * @param buffer Output buffer for the measurement hash.
 * @param length Size of the output buffer.
 *
 * @return Length of the hash that was generated for the measurement or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int pcr_hash_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	const struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer, size_t length)
{
	const struct pcr_measured_data *measured_data;
	int hash_length;
	bool include_event;
	bool include_version;
	int status = 0;

	if ((pcr == NULL) || (hash == NULL) || (buffer == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->config.num_measurements) {
		return PCR_INVALID_INDEX;
	}

	hash_length = hash_get_hash_length (hash_type);
	if (hash_length == HASH_ENGINE_UNKNOWN_HASH) {
		return hash_length;
	}

	if (length < (size_t) hash_length) {
		return PCR_SMALL_OUTPUT_BUFFER;
	}

	platform_mutex_lock (&pcr->lock);

	if (hash_type == pcr->config.measurement_algo) {
		/* No need to recalculate the hash since the requested algorithm matches the one used for
		 * all measurements in the PCR. */
		memcpy (buffer, pcr->measurement_list[measurement_index].digest, hash_length);
	}
	else {
		/* Calculate the digest from the raw measured data. */
		measured_data = pcr->measurement_list[measurement_index].measured_data;
		if (measured_data == NULL) {
			/* There is no measured data for this measurement, so it's not possible to calculate the
			 * hash */
			status = PCR_MEASURED_DATA_NOT_AVIALABLE;
			goto exit;
		}

		include_event = pcr->measurement_list[measurement_index].measurement_config &
			PCR_MEASUREMENT_FLAG_EVENT;
		include_version = pcr->measurement_list[measurement_index].measurement_config &
			PCR_MEASUREMENT_FLAG_VERSION;

		status = hash_start_new_hash (hash, hash_type);
		if (status != 0) {
			goto exit;
		}

		if (include_event) {
			status = hash->update (hash,
				(uint8_t*) &pcr->measurement_list[measurement_index].event_type, 4);
			if (status != 0) {
				goto hash_done;
			}
		}

		if (include_version) {
			status = hash->update (hash, &pcr->measurement_list[measurement_index].version, 1);
			if (status != 0) {
				goto hash_done;
			}
		}

		switch (measured_data->type) {
			case PCR_DATA_TYPE_1BYTE:
				status = hash->update (hash, &measured_data->data.value_1byte, 1);
				break;

			case PCR_DATA_TYPE_2BYTE:
				status = hash->update (hash, (uint8_t*) &measured_data->data.value_2byte, 2);
				break;

			case PCR_DATA_TYPE_4BYTE:
				status = hash->update (hash, (uint8_t*) &measured_data->data.value_4byte, 4);
				break;

			case PCR_DATA_TYPE_8BYTE:
				status = hash->update (hash, (uint8_t*) &measured_data->data.value_8byte, 8);
				break;

			case PCR_DATA_TYPE_MEMORY:
				status = hash->update (hash, measured_data->data.memory.buffer,
					measured_data->data.memory.length);
				break;

			case PCR_DATA_TYPE_FLASH:
				status = flash_hash_update_contents (measured_data->data.flash.flash,
					measured_data->data.flash.addr, measured_data->data.flash.length, hash);
				break;

			case PCR_DATA_TYPE_CALLBACK:
				if (measured_data->data.callback.hash_data != NULL) {
					status =
						measured_data->data.callback.hash_data (
						measured_data->data.callback.context, hash);
				}
				else {
					status = PCR_MEASURED_DATA_NO_HASH_CALLBACK;
				}
				break;

			default:
				status = PCR_INVALID_DATA_TYPE;
				break;
		}
		if (status != 0) {
			goto hash_done;
		}

		status = hash->finish (hash, buffer, length);
	}

hash_done:
	if (status == 0) {
		status = hash_length;
	}
	else {
		hash->cancel (hash);
	}

exit:
	platform_mutex_unlock (&pcr->lock);

	return status;
}

/**
 * Generate TCG formatted log entries for all measurements in the PCR.
 *
 * @param pcr The PCR to query.
 * @param pcr_num Number assigned to this PCR.
 * @param offset Offset within the PCR log to start reading data.
 * @param buffer Output buffer to populate with the requested log entries.
 * @param length Maximum number of bytes to read from the log.
 * @param total_len Total length of all log entries for the PCR.  This is only valid if the call is
 * successful and 0 bytes are read from the log.  This would happen if the offset was large enough
 * to skip over all the log data.
 *
 * @return The number of bytes read from the log or an error code.
 */
int pcr_get_tcg_log (struct pcr_bank *pcr, uint32_t pcr_num, size_t offset, uint8_t *buffer,
	size_t length, size_t *total_len)
{
	union {
		struct pcr_tcg_event2_header header;
		struct pcr_tcg_event2_sha256 sha256;
		struct pcr_tcg_event2_sha384 sha384;
		struct pcr_tcg_event2_sha512 sha512;
	} entry;
	size_t num_bytes = 0;
	size_t i = 0;
	uint8_t *entry_digest;
	uint32_t *entry_event_size;
	size_t entry_digest_len;
	size_t entry_total_len;
	uint8_t *entry_ptr = NULL;
	size_t entry_len = 0;
	size_t entry_offset = 0;
	size_t event_size;
	int status = 0;

	if ((pcr == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	*total_len = 0;

	if (pcr->explicit_measurement) {
		return 0;
	}

	entry.header.pcr_index = pcr_num;
	entry.header.digest_count = 1;

	switch (pcr->config.measurement_algo) {
		default:
		/* This isn't possible, since invalid hash types would be caught during init.
			 * Fall-through to SHA-256.  This is here mostly to keep compilers happy. */
		case HASH_TYPE_SHA256:
			entry.header.digest_algorithm_id = PCR_TCG_SHA256_ALG_ID;
			entry_digest = entry.sha256.digest;
			entry_event_size = &entry.sha256.event_size;
			entry_digest_len = SHA256_HASH_LENGTH;
			entry_total_len = sizeof (entry.sha256);
			break;

#if PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH
		case HASH_TYPE_SHA384:
			entry.header.digest_algorithm_id = PCR_TCG_SHA384_ALG_ID;
			entry_digest = entry.sha384.digest;
			entry_event_size = &entry.sha384.event_size;
			entry_digest_len = SHA384_HASH_LENGTH;
			entry_total_len = sizeof (entry.sha384);
			break;
#endif

#if PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH
		case HASH_TYPE_SHA512:
			entry.header.digest_algorithm_id = PCR_TCG_SHA512_ALG_ID;
			entry_digest = entry.sha512.digest;
			entry_event_size = &entry.sha512.event_size;
			entry_digest_len = SHA512_HASH_LENGTH;
			entry_total_len = sizeof (entry.sha512);
			break;
#endif
	}

	platform_mutex_lock (&pcr->lock);

	while ((i < pcr->config.num_measurements) && (length > 0)) {
		entry.header.event_type = pcr->measurement_list[i].event_type;

		memcpy (entry_digest, pcr->measurement_list[i].digest, entry_digest_len);

		*total_len += entry_total_len;

		if (offset >= entry_total_len) {
			offset -= entry_total_len;
		}
		else if (length > 0) {
			entry_len = min (entry_total_len - offset, length);
			entry_offset = offset;
			entry_ptr = buffer;

			/* Do not write the entry yet because we don't know the entry size, but update the state
			 * as if it was written to ensure everything ends up in the right place. */
			num_bytes += entry_len;
			buffer += entry_len;
			length -= entry_len;
			offset = 0;
		}

		/* The entry event size is not word-aligned, so use a temp location that is aligned. */
		status = pcr_get_measurement_data_internal (pcr, i, offset, buffer, length, &event_size);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		*entry_event_size = event_size;

		if (entry_ptr != NULL) {
			memcpy (entry_ptr, ((uint8_t*) &entry) + entry_offset, entry_len);
			entry_ptr = NULL;
		}

		*total_len += event_size;
		buffer += status;
		length -= status;

		if (status > 0) {
			offset = 0;
			num_bytes += status;
		}
		else {
			offset -= event_size;
		}

		i++;
	}

exit:
	platform_mutex_unlock (&pcr->lock);

	if (ROT_IS_ERROR (status)) {
		return status;
	}
	else {
		return num_bytes;
	}
}

/**
 * Acquire the lock for accessing the PCR measurements.
 *
 * @param pcr The PCR to lock.
 *
 * @return Completion status, 0 if success or an error code.
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
 * Release the lock for accessing the PCR measurements.
 *
 * @param pcr The PCR to unlock.
 *
 * @return Completion status, 0 if success or an error code.
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
