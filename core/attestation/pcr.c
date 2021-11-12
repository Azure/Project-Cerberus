// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "common/common_math.h"
#include "flash/flash.h"
#include "platform.h"
#include "pcr.h"


/**
 * Common function to update digest in PCR bank's list of measurements
 *
 * @param pcr PCR bank to update
 * @param measurement_index The index of measurement being updated
 * @param digest Buffer holding digest to add
 * @param digest_len Length of digest buffer
 * @param measurement_config Indicates data included in measurement calculation
 * @param version Version to associate with the measurement data
 *
 * @return 0 if successful or an error code
 */
static int pcr_update_digest_common (struct pcr_bank *pcr, uint8_t measurement_index,
	const uint8_t *digest, size_t digest_len, uint8_t measurement_config, uint8_t version)
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
	pcr->measurement_list[measurement_index].measurement_config = measurement_config;
	pcr->measurement_list[measurement_index].version = version;

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Common function to compute digest of buffer and update the PCR bank's list of measurements
 *
 * @param pcr PCR bank to update measurement in
 * @param hash Hashing engine to utilize
 * @param measurement_index The index of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param include_version Flag that indicates whether to include the version in measurement
 * calculations
 * @param version The version associated with the measurement data
 *
 * @return Completion status, 0 if success or an error code
 */
static int pcr_update_buffer_common (struct pcr_bank *pcr, struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	bool include_version, uint8_t version)
{
	uint8_t digest[PCR_DIGEST_LENGTH];
	uint8_t config = 0;
	int status;

	status = hash->start_sha256 (hash);
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

	status = hash->update (hash, buf, buf_len);
	if (status != 0) {
		goto hash_cancel;
	}

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		goto hash_cancel;
	}

	return pcr_update_digest_common (pcr, measurement_index, digest, sizeof (digest), config,
		version);

hash_cancel:
	hash->cancel (hash);

	return status;
}

/**
 * Read the measurement data bytes and copy the data to the provided buffer
 *
 * @param buffer Output buffer containing the measured data
 * @param buffer_len Maximum length of the buffer
 * @param data Buffer storing the measurement data to be read
 * @param data_len Size in bytes of the measurement data
 * @param offset The offset index to read from
 *
 * @return total number of bytes read
 */
static int pcr_read_measurement_data_bytes (uint8_t *buffer, size_t buffer_len, const uint8_t *data,
	size_t data_len, size_t offset)
{
	int bytes_read;

	if ((buffer_len == 0) || (offset > data_len - 1)) {
		return 0;
	}

	bytes_read = ((data_len - offset) > buffer_len) ?  buffer_len : (data_len - offset);
	memcpy (buffer, data + offset, bytes_read);

	return bytes_read;
}

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
		pcr->explicit_measurement = true;
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
 * Update digest in PCR bank's list of measurements and reset measurement configuration
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
	return pcr_update_digest_common (pcr, measurement_index, digest, digest_len, 0, 0);
}

/**
 * Compute digest of buffer and update the PCR bank's list of measurements
 *
 * @param pcr PCR bank to update measurement in
 * @param hash Hashing engine to utilize
 * @param measurement_index The index of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_update_buffer (struct pcr_bank *pcr, struct hash_engine *hash, uint8_t measurement_index,
	const uint8_t *buf, size_t buf_len, bool include_event)
{
	if ((pcr == NULL) || (buf == NULL) || (buf_len == 0) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len, include_event,
		false, 0);
}

/**
 * Compute digest of versioned buffer and update the PCR bank's list of measurements
 *
 * @param pcr PCR bank to update measurement in
 * @param hash Hashing engine to utilize
 * @param measurement_index The index of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param version The version associated with the measurement data
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_update_versioned_buffer (struct pcr_bank *pcr, struct hash_engine *hash,
	uint8_t measurement_index, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version)
{
	if ((pcr == NULL) || (buf == NULL) || (buf_len == 0) || (hash == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	return pcr_update_buffer_common (pcr, hash, measurement_index, buf, buf_len,
		include_event, true, version);
}

/**
 * Update event type for a measurement in the PCR bank
 *
 * @param pcr PCR bank to update measurement in
 * @param measurement_index The index of measurement being updated
 * @param event_type Event type to associate with measurement
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_update_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t event_type)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	platform_mutex_lock (&pcr->lock);

	pcr->measurement_list[measurement_index].event_type = event_type;

	platform_mutex_unlock (&pcr->lock);

	return 0;
}

/**
 * Get the event type for a measurement in the PCR bank
 *
 * @param pcr PCR bank to retrieve measurement data
 * @param measurement_index The index of measurement being accessed
 * @param event_type Output buffer to store the event type
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_get_event_type (struct pcr_bank *pcr, uint8_t measurement_index, uint32_t *event_type)
{
	if ((pcr == NULL) || (event_type == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	*event_type = pcr->measurement_list[measurement_index].event_type;

	return 0;
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

	if (!pcr->explicit_measurement) {
		for (i_measurement = 0; i_measurement < (int) pcr->num_measurements; ++i_measurement) {
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

	if (pcr->explicit_measurement) {
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
 * Set the measured data for PCR bank
 *
 * @param pcr The PCR bank to set measurement data for
 * @param measurement_index Index of measurement to set
 * @param measurement_data buffer containing the measured data
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_set_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index,
	struct pcr_measured_data *measurement_data)
{
	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
		return PCR_INVALID_INDEX;
	}

	if (measurement_data != NULL) {
		switch (measurement_data->type) {
			case PCR_DATA_TYPE_1BYTE:
			case PCR_DATA_TYPE_2BYTE:
			case PCR_DATA_TYPE_4BYTE:
			case PCR_DATA_TYPE_8BYTE:
				break;

			case PCR_DATA_TYPE_MEMORY:
				if (measurement_data->data.memory.buffer == NULL) {
					return PCR_MEASURED_DATA_INVALID_MEMORY;
				}
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

	pcr->measurement_list[measurement_index].measured_data = measurement_data;

	return 0;
}

/**
 * Internal function to retrieve the measured data from PCR bank
 *
 * @param pcr The PCR bank to get measurement data from.
 * @param measurement_index Index of measurement to set.
 * @param offset The offset index to read from.
 * @param buffer Output buffer containing the measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer containing the total length of the measurement data. This should
 * 	contain total length of the measured data even if only partially returned.
 *
 * @return length of the buffer if measured data was retrieved successfully or an error code
 */
static int pcr_get_measurement_data_internal (struct pcr_bank *pcr, uint8_t measurement_index,
	size_t offset, uint8_t *buffer, size_t length, uint32_t *total_len)
{
	struct pcr_measured_data *measured_data;
	bool include_event;
	bool include_version;
	size_t total_bytes = 0;
	size_t bytes_read;
	uint32_t data_len;
	int status = 0;

	if ((pcr == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	if (measurement_index >= pcr->num_measurements) {
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
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				(uint8_t*) &pcr->measurement_list[measurement_index].event_type, 4, offset);
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
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				&pcr->measurement_list[measurement_index].version, 1, offset);
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
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				&measured_data->data.value_1byte, 1, offset);
			status = bytes_read + total_bytes;
			*total_len += 1;
			break;

		case PCR_DATA_TYPE_2BYTE:
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				(uint8_t*) &measured_data->data.value_2byte, 2, offset);
			status = bytes_read + total_bytes;
			*total_len += 2;
			break;

		case PCR_DATA_TYPE_4BYTE:
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				(uint8_t*) &measured_data->data.value_4byte, 4, offset);
			status = bytes_read + total_bytes;
			*total_len += 4;
			break;

		case PCR_DATA_TYPE_8BYTE:
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				(uint8_t*) &measured_data->data.value_8byte, 8, offset);
			status = bytes_read + total_bytes;
			*total_len += 8;
			break;

		case PCR_DATA_TYPE_MEMORY:
			bytes_read = pcr_read_measurement_data_bytes (buffer, length,
				measured_data->data.memory.buffer, measured_data->data.memory.length, offset);
			status = bytes_read + total_bytes;
			*total_len += measured_data->data.memory.length;
			break;

		case PCR_DATA_TYPE_FLASH: {
			struct flash *flash_device = measured_data->data.flash.flash;
			size_t read_addr = measured_data->data.flash.addr + offset;

			if (offset > (measured_data->data.flash.length - 1)) {
				status = total_bytes;
			}
			else {
				bytes_read = ((measured_data->data.flash.length - offset) > length ? length :
					(measured_data->data.flash.length - offset));

				status = flash_device->read (flash_device, read_addr, buffer, bytes_read);
				if (status == 0) {
					status = bytes_read + total_bytes;
				}
			}

			*total_len += measured_data->data.flash.length;
			break;
		}

		case PCR_DATA_TYPE_CALLBACK: {
			status = measured_data->data.callback.get_data (measured_data->data.callback.context,
				offset, buffer, length, &data_len);
			if (!ROT_IS_ERROR (status)) {
				status = status + total_bytes;
			}

			*total_len += data_len;

			break;
		}

		default:
			status = PCR_INVALID_DATA_TYPE;
	}

	return status;
}

/**
 * Retrieve the measured data from PCR bank
 *
 * @param pcr The PCR bank to get measurement data from.
 * @param measurement_index Index of measurement to set.
 * @param offset The offset index to read from.
 * @param buffer Output buffer containing the measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer containing the total length of the measurement data. This should
 * 	contain total length of the measured data even if only partially returned.
 *
 * @return length of the buffer if measured data was retrieved successfully or an error code
 */
int pcr_get_measurement_data (struct pcr_bank *pcr, uint8_t measurement_index, size_t offset,
	 uint8_t *buffer, size_t length, uint32_t *total_len)
{
	int status;

	if (pcr == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&pcr->lock);

	status = pcr_get_measurement_data_internal (pcr, measurement_index, offset, buffer, length,
		total_len);

	platform_mutex_unlock (&pcr->lock);

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

	if (pcr->explicit_measurement) {
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

/**
 * Generate TCG formatted log entries for PCR bank.
 *
 * @param pcr PCR bank to utilize.
 * @param pcr_num PCR bank number.
 * @param buffer Buffer to populate with requested log entries.
 * @param offset Offset within the log to start reading data.
 * @param length Maximum number of bytes to read from the log.
 * @param total_len Total length of log entries for PCR bank.  This is only valid if the call is
 * successful and 0 bytes are read from the log.
 *
 * @return The number of bytes read from the log or an error code.
 */
int pcr_get_tcg_log (struct pcr_bank *pcr, uint32_t pcr_num, uint8_t *buffer, size_t offset,
	size_t length, size_t *total_len)
{
	struct pcr_tcg_event2 entry;
	size_t num_bytes = 0;
	size_t i_measurement = 0;
	uint8_t *entry_ptr = NULL;
	size_t entry_len = 0;
	size_t entry_offset = 0;
	int status = 0;

	if ((pcr == NULL) || (buffer == NULL) || (total_len == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	*total_len = 0;

	if (pcr->explicit_measurement) {
		return 0;
	}

	entry.pcr_bank = pcr_num;
	entry.digest_count = 1;
	entry.digest_algorithm_id = PCR_TCG_SHA256_ALG_ID;

	platform_mutex_lock (&pcr->lock);

	while ((i_measurement < pcr->num_measurements) && (length > 0)) {
		entry.event_type = pcr->measurement_list[i_measurement].event_type;

		memcpy (entry.digest, pcr->measurement_list[i_measurement].digest,
			sizeof (pcr->measurement_list[i_measurement].digest));

		*total_len += sizeof (struct pcr_tcg_event2);

		if (offset >= sizeof (struct pcr_tcg_event2)) {
			offset -= sizeof (struct pcr_tcg_event2);
		}
		else if (length > 0) {
			entry_len = min (sizeof (struct pcr_tcg_event2) - offset, length);
			entry_offset = offset;
			entry_ptr = buffer;

			/* Do not write the entry yet because we don't know the entry size, but update the state
			 * as if it was written to ensure everything ends up in the right place. */
			num_bytes += entry_len;
			buffer += entry_len;
			length -= entry_len;
			offset = 0;
		}

		status = pcr_get_measurement_data_internal (pcr, i_measurement, offset, buffer, length,
			&entry.event_size);
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		if (entry_ptr != NULL) {
			memcpy (entry_ptr, ((uint8_t*) &entry) + entry_offset, entry_len);
			entry_ptr = NULL;
		}

		*total_len += entry.event_size;
		buffer += status;
		length -= status;

		if (status > 0) {
			offset = 0;
			num_bytes += status;
		}
		else {
			offset -= entry.event_size;
		}

		i_measurement++;
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
