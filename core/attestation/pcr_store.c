// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "common/common_math.h"
#include "pcr_store.h"
#include "pcr.h"
#include "pcr_data.h"


/**
 * Initialize all PCR banks in PCR store with the provided number of measurements to support
 *
 * @param store PCR store to initialize
 * @param num_pcr_measurements The number of measurements to initialize each PCR bank to hold.  If
 * a bank is configured to hold no measurements, a single, explicit measurement can be stored.
 * @param num_pcr The number of PCRs in num_pcr_measurements array
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_init (struct pcr_store *store, uint8_t *num_pcr_measurements, size_t num_pcr)
{
	size_t i_pcr;
	int status;

	if ((store == NULL) || (num_pcr_measurements == NULL) || (num_pcr == 0)) {
		return PCR_INVALID_ARGUMENT;
	}

	store->banks = platform_malloc (sizeof (struct pcr_bank) * num_pcr);
	if (store->banks == NULL) {
		return PCR_NO_MEMORY;
	}

	store->num_pcr_banks = num_pcr;

	for (i_pcr = 0; i_pcr < num_pcr; ++i_pcr) {
		status = pcr_init (&store->banks[i_pcr], num_pcr_measurements[i_pcr]);
		if (status != 0) {
			while (i_pcr > 0) {
				--i_pcr;
				pcr_release (&store->banks[i_pcr]);
			}

			platform_free (store->banks);

			return status;
		}
	}

	return status;
}

/**
 * Release resources held by all banks in PCR store
 *
 * @param store PCR store to release
 */
void pcr_store_release (struct pcr_store *store)
{
	uint8_t i_pcr;

	if (store != NULL) {
		for (i_pcr = 0; i_pcr < store->num_pcr_banks; ++i_pcr) {
			pcr_release (&store->banks[i_pcr]);
		}

		platform_free (store->banks);
	}
}

/**
 * Indicate if a measurement type is valid for the PCR store.
 *
 * @param store The PCR store to query.
 * @param measurement_type The measurement type to check.
 *
 * @return 0 if the measurement type is valid or an error code.
 */
int pcr_store_check_measurement_type (struct pcr_store *store, uint16_t measurement_type)
{
	uint8_t pcr_bank = measurement_type >> 8;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_check_measurement_index (&store->banks[pcr_bank], (uint8_t) measurement_type);
}

/**
 * Retrieve number of PCR banks initialized in store
 *
 * @param store PCR store to utilize
 *
 * @return Number of pcr banks if successful or an error code
 */
int pcr_store_get_num_banks (struct pcr_store *store)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	return store->num_pcr_banks;
}

/**
 * Update digest in PCR bank's list of measurements
 *
 * @param store PCR store containing PCR to be updated
 * @param measurement_type The type of measurement being added
 * @param digest Buffer holding digest to add
 * @param digest_len Length of digest buffer
 *
 * @return 0 if successful or an error code
 */
int pcr_store_update_digest (struct pcr_store *store, uint16_t measurement_type,
	const uint8_t *digest, size_t digest_len)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_digest (&store->banks[pcr_bank], measurement_index, digest, digest_len);
}

/**
 * Compute digest of buffer and update the PCR bank's list of measurements
 *
 * @param store PCR store containing PCR to be updated
 * @param hash Hashing engine to utilize in PCR bank operations
 * @param measurement_type The type of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations.
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_update_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_buffer (&store->banks[pcr_bank], hash, measurement_index, buf, buf_len,
		include_event);
}

/**
 * Compute digest of the versioned buffer and update the PCR bank's list of measurements
 *
 * @param store PCR store containing PCR to be updated
 * @param hash Hashing engine to utilize in PCR bank operations
 * @param measurement_type The type of measurement being updated
 * @param buf Buffer holding data to compute measurement of
 * @param buf_len Length of data buffer
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param version The version associated with the measurement data.
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_update_versioned_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_versioned_buffer (&store->banks[pcr_bank], hash, measurement_index, buf,
		buf_len, include_event, version);
}

/**
 * Update event type in PCR bank's list of measurements
 *
 * @param store PCR store containing PCR to be updated
 * @param measurement_type The type of measurement being added
 * @param event_type TCG event type to associate measurement with
 *
 * @return 0 if successful or an error code
 */
int pcr_store_update_event_type (struct pcr_store *store, uint16_t measurement_type,
	uint32_t event_type)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_event_type (&store->banks[pcr_bank], measurement_index, event_type);
}

/**
 * Compute aggregate of all measurements that have added to PCR bank
 *
 * @param store PCR store containing PCR to be utilized
 * @param hash Hashing engine to utilize in PCR bank operations
 * @param pcr_num The PCR bank to compute aggregate measurement of
 * @param measurement The output PCR measurement
 *
 * @return The number of digests included in the calculated measurement.
 */
int pcr_store_compute (struct pcr_store *store, struct hash_engine *hash, uint8_t pcr_num,
	uint8_t *measurement)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_num >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_compute (&store->banks[pcr_num], hash, measurement, true);
}

/**
 * Retrieve a specific measurement that is part of the PCR store
 *
 * @param store PCR store containing measurement to be retrieved
 * @param measurement_type Measurement type which indicates PCR bank and measurement index
 * @param measurement The output PCR measurement
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_get_measurement (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measurement *measurement)
{
	uint8_t pcr_bank = (uint8_t)(measurement_type >> 8);
	uint8_t measurement_index = (uint8_t)measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_measurement (&store->banks[pcr_bank], measurement_index, measurement);
}

/**
 * Set measurement data for a specific measurement that is part of the PCR store
 *
 * @param store PCR store containing measurement for which measurement data is to be set
 * @param measurement_type Measurement type which indicates PCR bank and measurement index
 * @param measurement_data The buffer containing the measurement data
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_set_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measured_data *measured_data)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_set_measurement_data (&store->banks[pcr_bank], measurement_index, measured_data);
}

/**
 * Get measurement data of a specific measurement that is part of the PCR store
 *
 * @param store PCR store containing measurement for which measurement data needs to be set
 * @param measurement_type Measurement type which indicates PCR bank and measurement index
 * @param offset The offset index to read from
 * @param buffer Output buffer to be filled with the measurement data
 * @param length Length of the buffer.
 *
 * @return length of the measuremenet data if successfully retrieved or an error code
 */
int pcr_store_get_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	size_t offset, uint8_t *buffer, size_t length)
{
	uint8_t pcr_bank = (uint8_t) (measurement_type >> 8);
	uint8_t measurement_index = (uint8_t) measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_measurement_data (&store->banks[pcr_bank], measurement_index, offset, buffer,
		length);
}

/**
 * Invalidate a specific measurement that is part of the PCR store
 *
 * @param store PCR store containing measurement to be invalidated
 * @param measurement_type Measurement type that indicates PCR bank and measurement index
 *
 * @return Completion status, 0 if success or an error code
 */
int pcr_store_invalidate_measurement (struct pcr_store *store, uint16_t measurement_type)
{
	uint8_t pcr_bank = (uint8_t)(measurement_type >> 8);
	uint8_t measurement_index = (uint8_t)measurement_type;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_bank >= store->num_pcr_banks) {
		return PCR_INVALID_PCR;
	}

	return pcr_invalidate_measurement_index (&store->banks[pcr_bank], measurement_index);
}

/**
 * Get number of measurements in all PCR banks
 *
 * @param store PCR store to get number of measurements from
 *
 * @return Number of measurements or an error code
 */
static int pcr_store_get_num_measurements (struct pcr_store *store)
{
	int num_measurements = 0;
	int i_bank;
	int status;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	for (i_bank = 0; i_bank < store->num_pcr_banks; ++i_bank) {
		status = pcr_get_num_measurements (&store->banks[i_bank]);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		num_measurements += status;
	}

	return num_measurements;
}

/**
 * Get size of TCG log if constructed by PCR store
 *
 * @param store PCR store to get TCG log size from
 *
 * @return TCG log size or an error code
 */
int pcr_store_get_tcg_log_size (struct pcr_store *store)
{
	int status;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	status = pcr_store_get_num_measurements (store);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	return (status * sizeof (struct pcr_store_tcg_log_entry));
}

/**
 * Generate TCG log from PCR banks.
 *
 * @param store PCR store to get measurements from.
 * @param hash Hashing engine to utilize in PCR bank operations.
 * @param offset Offset within the log to start reading data.
 * @param contents Output buffer for the log contents.
 * @param length Maximum number of bytes to read from the log.
 *
 * @return The number of bytes read from the log or an error code.
 */
int pcr_store_get_tcg_log (struct pcr_store *store, struct hash_engine *hash, uint32_t offset,
	uint8_t *contents, size_t length)
{
	struct pcr_store_tcg_log_entry log_entry;
	const struct pcr_measurement *measurements;
	uint32_t contents_offset = 0;
	uint32_t entry_length;
	uint32_t entry_offset;
	uint32_t i_entry = 0;
	uint8_t i_bank;
	int starting_measurement;
	int total_log_size = 0;
	int num_measurements;
	int i_measurement;
	int status;

	if ((store == NULL) || (hash == NULL) || (contents == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	for (i_bank = 0; i_bank < store->num_pcr_banks; ++i_bank) {
		status = pcr_lock (&store->banks[i_bank]);
		if (status != 0) {
			return status;
		}

		status = pcr_compute (&store->banks[i_bank], hash, NULL, false);
		if (ROT_IS_ERROR (status)) {
			pcr_unlock (&store->banks[i_bank]);
			return status;
		}

		num_measurements = pcr_get_num_measurements (&store->banks[i_bank]);
		if (ROT_IS_ERROR (num_measurements)) {
			pcr_unlock (&store->banks[i_bank]);
			return num_measurements;
		}

		if (num_measurements == 0) {
			pcr_unlock (&store->banks[i_bank]);
			continue;
		}

		num_measurements = pcr_get_all_measurements (&store->banks[i_bank],
			(const uint8_t**) &measurements);
		if (ROT_IS_ERROR (num_measurements)) {
			pcr_unlock (&store->banks[i_bank]);
			return num_measurements;
		}

		if (total_log_size >= offset) {
			total_log_size += num_measurements * sizeof (struct pcr_store_tcg_log_entry);
			starting_measurement = 0;
			entry_offset = 0;
		}
		else {
			starting_measurement = (offset - total_log_size) /
				sizeof (struct pcr_store_tcg_log_entry);
			entry_offset = (offset - total_log_size) - (starting_measurement) *
				sizeof (struct pcr_store_tcg_log_entry);
			total_log_size += num_measurements * sizeof (struct pcr_store_tcg_log_entry);

			if (total_log_size <= offset) {
				i_entry += num_measurements;
				pcr_unlock (&store->banks[i_bank]);
				continue;
			}

			i_entry += starting_measurement;
		}

		for (i_measurement = 0; i_measurement < num_measurements; ++i_measurement) {
			if (i_measurement < starting_measurement) {
				continue;
			}

			log_entry.header.log_magic = LOGGING_MAGIC_START;
			log_entry.header.length = sizeof (struct pcr_store_tcg_log_entry);
			log_entry.header.entry_id = i_entry++;

			log_entry.entry.digest_algorithm_id = 0x0B;
			log_entry.entry.digest_count = 1;
			log_entry.entry.event_type = measurements[i_measurement].event_type;
			log_entry.entry.measurement_type = PCR_MEASUREMENT (i_bank, i_measurement);
			log_entry.entry.measurement_size = sizeof (measurements[i_measurement].digest);

			memcpy (log_entry.entry.digest, measurements[i_measurement].digest,
				sizeof (measurements[i_measurement].digest));
			memcpy (log_entry.entry.measurement, measurements[i_measurement].measurement,
				sizeof (measurements[i_measurement].measurement));

			entry_length = min (length - contents_offset,
				sizeof (struct pcr_store_tcg_log_entry) - entry_offset);

			memcpy (&contents[contents_offset], ((uint8_t*) &log_entry) + entry_offset,
				entry_length);

			contents_offset += entry_length;
			if (contents_offset >= length) {
				pcr_unlock (&store->banks[i_bank]);
				return contents_offset;
			}

			entry_offset = 0;
		}

		pcr_unlock (&store->banks[i_bank]);
	}

	return contents_offset;
}
