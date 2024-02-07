// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "pcr_store.h"
#include "pcr.h"
#include "pcr_data.h"


/**
 * Get the PCR index from a measurement identifier.
 */
#define	PCR_STORE_PCR_INDEX(x)				(((x) >> 8) & 0xff)

/**
 * Get the measurement index within a PCR from the measurement identifier.
 */
#define	PCR_STORE_MEASUREMENT_INDEX(x)		((x) & 0xff)


/**
 * Initialize storage for all device PCRs.
 *
 * @param store The PCR storage to initialize.
 * @param pcr_config An array containing configuration information for each of the PCRs that should
 * be managed.  If any PCR is configured to hold no measurements, a single, explicit measurement can
 * be stored in that PCR.
 * @param num_pcrs The number of PCR configurations provided, which indicates the number of PCRs
 * that will be managed.
 *
 * @return Completion status, 0 if success or an error code.
 */
int pcr_store_init (struct pcr_store *store, const struct pcr_config *pcr_config, size_t num_pcrs)
{
	size_t i;
	int status;

	if ((store == NULL) || (pcr_config == NULL) || (num_pcrs == 0)) {
		return PCR_INVALID_ARGUMENT;
	}

	store->pcrs = platform_malloc (sizeof (struct pcr_bank) * num_pcrs);
	if (store->pcrs == NULL) {
		return PCR_NO_MEMORY;
	}

	store->num_pcrs = num_pcrs;

	for (i = 0; i < num_pcrs; ++i) {
		status = pcr_init (&store->pcrs[i], &pcr_config[i]);
		if (status != 0) {
			while (i > 0) {
				pcr_release (&store->pcrs[--i]);
			}

			platform_free (store->pcrs);
			return status;
		}
	}

	return status;
}

/**
 * Release resources used for PCR storage.
 *
 * @param store The PCR storage to release.
 */
void pcr_store_release (struct pcr_store *store)
{
	size_t i;

	if (store != NULL) {
		for (i = 0; i < store->num_pcrs; ++i) {
			pcr_release (&store->pcrs[i]);
		}

		platform_free (store->pcrs);
	}
}

/**
 * Indicate if a measurement type is valid for the PCR store.
 *
 * @param store The PCR store to query.
 * @param measurement_type Measurement identifier to check for validity.
 *
 * @return 0 if the measurement type is valid or an error code.
 */
int pcr_store_check_measurement_type (struct pcr_store *store, uint16_t measurement_type)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_check_measurement_index (&store->pcrs[pcr_index],
		PCR_STORE_MEASUREMENT_INDEX (measurement_type));
}

/**
 * Retrieve the total number of PCRs in the store.
 *
 * @param store The PCR store to query.
 *
 * @return The number of PCRs or an error code.
 */
int pcr_store_get_num_pcrs (struct pcr_store *store)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	return store->num_pcrs;
}

/**
 * Get the total number of measurements in all PCRs.
 *
 * @param store PCR store to query.
 *
 * @return The total number of measurements or an error code.
 */
int pcr_store_get_num_total_measurements (struct pcr_store *store)
{
	int num_measurements = 0;
	size_t i;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	for (i = 0; i < store->num_pcrs; ++i) {
		num_measurements += pcr_get_num_measurements (&store->pcrs[i]);
	}

	return num_measurements;
}

/**
 * Get the number of measurements in a single PCR.  An explicit PCR value will report has having no
 * measurements.
 *
 * @param store The PCR store that contains the PCR to query.
 * @param pcr_num The index of the PCR to query.
 *
 * @return The number of measurements in the PCR or an error code.
 */
int pcr_store_get_num_pcr_measurements (struct pcr_store *store, uint8_t pcr_num)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_num >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_num_measurements (&store->pcrs[pcr_num]);
}

/**
 * Get the digest length used by a single PCR.
 *
 * @param store The PCR store that contains the PCR to query.
 * @param pcr_num The index of the PCR to query.
 *
 * @return The digest length used by the PCR or an error code.
 */
int pcr_store_get_pcr_digest_length (struct pcr_store *store, uint8_t pcr_num)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_num >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_digest_length (&store->pcrs[pcr_num]);
}

/**
 * Set the TCG event type for a single measurement.
 *
 * @param store The PCR store containing the measurement to update.
 * @param measurement_type Identifier for the measurement to update.
 * @param event_type TCG event type to associate with the measurement.
 *
 * @return 0 if the event type was set successfully or an error code.
 */
int pcr_store_set_tcg_event_type (struct pcr_store *store, uint16_t measurement_type,
	uint32_t event_type)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_set_event_type (&store->pcrs[pcr_index], measurement_index, event_type);
}

/**
 * Store a pre-computed digest for a single measurement in the PCR store.
 *
 * @param store The PCR store containing measurement to update.
 * @param measurement_type Identifier for the measurement to update.
 * @param digest The digest data that should be stored for the measurement.
 * @param digest_len Length of digest.  This must match exactly the digest length for the PCR.
 *
 * @return 0 if the digest was stored successfully or an error code.
 */
int pcr_store_update_digest (struct pcr_store *store, uint16_t measurement_type,
	const uint8_t *digest, size_t digest_len)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_digest (&store->pcrs[pcr_index], measurement_index, digest, digest_len);
}

/**
 * Update a specified measurement in the PCR store by computing the digest of a data buffer.
 *
 * @param store The PCR store containing measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_type Identifier for the measurement to update.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations.
 *
 * @return 0 if the measurement was updated successfully or an error code.
 */
int pcr_store_update_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_buffer (&store->pcrs[pcr_index], hash, measurement_index, buf, buf_len,
		include_event);
}

/**
 * Update a specified measurement in the PCR store by computing the digest of a versioned data
 * buffer.
 *
 * @param store The PCR store containing measurement to update.
 * @param hash Hashing engine to use for digest calculation.
 * @param measurement_type Identifier for the measurement to update.
 * @param buf Buffer holding the data to measure.
 * @param buf_len Length of data buffer.
 * @param include_event Flag that indicates whether to include the event type in measurement
 * calculations
 * @param version The version associated with the measurement data, which will prepended when
 * calculating the digest.
 *
 * @return 0 if the measurement was updated successfully or an error code.
 */
int pcr_store_update_versioned_buffer (struct pcr_store *store, struct hash_engine *hash,
	uint16_t measurement_type, const uint8_t *buf, size_t buf_len, bool include_event,
	uint8_t version)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_update_versioned_buffer (&store->pcrs[pcr_index], hash, measurement_index, buf,
		buf_len, include_event, version);
}

/**
 * Clear the currently stored digest for a measurement in the PCR store.
 *
 * @param store The PCR store containing measurement to be cleared.
 * @param measurement_type Identifier for the measurement to clear.
 *
 * @return 0 if the measurement digest was cleared successfully or an error code.
 */
int pcr_store_invalidate_measurement (struct pcr_store *store, uint16_t measurement_type)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_invalidate_measurement (&store->pcrs[pcr_index], measurement_index);
}

/**
 * Compute a single PCR value based on the current state of the measurements in the PCR store.  All
 * measurements for the PCR will be included in the calculation, even if they have not been updated
 * with a value or if they have been invalidated.
 *
 * @param store The PCR store that contains the PCR value to calculate.
 * @param hash Hashing engine to use for the calculation.
 * @param pcr_num The index of the PCR to compute.
 * @param measurement Optional output buffer to return the PCR value.  Setting this to null will
 * still refresh the measurement state.
 * @param length Size of the PCR output buffer, if one is provided.
 *
 * @return Length of the generated PCR value or an error code.  Use ROT_IS_ERROR to check the return
 * status.
 */
int pcr_store_compute_pcr (struct pcr_store *store, struct hash_engine *hash, uint8_t pcr_num,
	uint8_t *measurement, size_t length)
{
	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_num >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_compute (&store->pcrs[pcr_num], hash, true, measurement, length);
}

/**
 * Retrieve a specific measurement from the PCR store.
 *
 * @param store The PCR store containing the requested measurement.
 * @param measurement_type Identifier for the measurement to retrieve.
 * @param measurement Output for the measurement information.
 *
 * @return Length of the measurement digest or an error code.  Use ROT_IS_ERROR to check the return
 * status.
 */
int pcr_store_get_measurement (struct pcr_store *store, uint16_t measurement_type,
	struct pcr_measurement *measurement)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_measurement (&store->pcrs[pcr_index], measurement_index, measurement);
}

/**
 * Provide a descriptor for accessing the raw data that was measured for a specific measurement in
 * the PCR store.
 *
 * @param store The PCR store containing measurement to update with the data descriptor.
 * @param measurement_type Identifier for the measurement to update.
 * @param measurement_data Descriptor for the raw data associated with the measurement.
 *
 * @return 0 if the measured data descriptor was set successfully or an error code.
 */
int pcr_store_set_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	const struct pcr_measured_data *measured_data)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_set_measurement_data (&store->pcrs[pcr_index], measurement_index, measured_data);
}

/**
 * Retrieve the raw data that was used to generate a measurement in the PCR store.
 *
 * Measured data will be read until there is no more data or the output buffer is full, which ever
 * comes first.  There is no direct indication that the complete data has been retrieved.  A
 * subsequent call with the offset and/or length adjusted would be needed to determine if there is
 * more data available.
 *
 * @param store The PCR store containing the measurement to query.
 * @param measurement_type Identifier for the measurement to query.
 * @param offset An offset indicating where in the measurement data to start reading from.
 * @param buffer Output buffer for the measurement data.
 * @param length Length of the output buffer.
 *
 * @return The amount of data that was written into the output buffer or an error code.  Use
 * ROT_IS_ERROR to check the return value.
 */
int pcr_store_get_measurement_data (struct pcr_store *store, uint16_t measurement_type,
	size_t offset, uint8_t *buffer, size_t length)
{
	uint8_t pcr_index = PCR_STORE_PCR_INDEX (measurement_type);
	uint8_t measurement_index = PCR_STORE_MEASUREMENT_INDEX (measurement_type);
	uint32_t total_len;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	if (pcr_index >= store->num_pcrs) {
		return PCR_INVALID_PCR;
	}

	return pcr_get_measurement_data (&store->pcrs[pcr_index], measurement_index, offset, buffer,
		length, &total_len);
}

/**
 * Get the total size of attestation log for the PCR store.
 *
 * @param store The PCR store to query.
 *
 * @return Total length of the attestation log or an error code.  Use ROT_IS_ERROR to check the
 * return value.
 */
int pcr_store_get_attestation_log_size (struct pcr_store *store)
{
	size_t log_size = 0;
	size_t i;
	int count;

	if (store == NULL) {
		return PCR_INVALID_ARGUMENT;
	}

	for (i = 0; i < store->num_pcrs; i++) {
		count = pcr_get_num_measurements (&store->pcrs[i]);

		switch (pcr_get_hash_algorithm (&store->pcrs[i])) {
			case HASH_TYPE_SHA256:
				log_size += (count * sizeof (struct pcr_store_attestation_log_entry_sha256));
				break;

#if PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH
			case HASH_TYPE_SHA384:
				log_size += (count * sizeof (struct pcr_store_attestation_log_entry_sha384));
				break;
#endif

#if PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH
			case HASH_TYPE_SHA512:
				log_size += (count * sizeof (struct pcr_store_attestation_log_entry_sha512));
				break;
#endif

			default:
				/* Not possible. */
				break;
		}
	}

	return log_size;
}

/**
 * Read the attestation log from the PCR store, which will cause the current value of all PCRs to be
 * calculated.
 *
 * Only data that will fit into the provided buffer will be returned.  Additional calls with
 * different length/offset values would be needed to get the remaining data.
 *
 * @param store The PCR store to query for log data.
 * @param hash Hashing engine to use for PCR calculations.
 * @param offset Offset within the log to start reading data.
 * @param contents Output buffer for the log contents.
 * @param length Maximum number of bytes to read from the log.
 *
 * @return The number of bytes read from the log or an error code.
 */
int pcr_store_get_attestation_log (struct pcr_store *store, struct hash_engine *hash,
	size_t offset, uint8_t *contents, size_t length)
{
	union {
		struct pcr_store_attestation_log_entry_base base;
		struct pcr_store_attestation_log_entry_sha256 sha256;
		struct pcr_store_attestation_log_entry_sha384 sha384;
		struct pcr_store_attestation_log_entry_sha512 sha512;
	} log_entry;
	const struct pcr_measurement *measurements;
	uint8_t *digest;
	uint32_t *measurement_size;
	uint8_t *measurement;
	uint32_t entry_length;
	uint16_t algorithm_id;
	uint32_t entry_id = 0;
	size_t entry_bytes;
	size_t total_bytes = 0;
	size_t pcr;
	int digest_length;
	int num_measurements;
	int i;
	int status;

	if ((store == NULL) || (hash == NULL) || (contents == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	pcr = 0;
	while ((pcr < store->num_pcrs) && (length > 0)) {
		num_measurements = pcr_get_num_measurements (&store->pcrs[pcr]);
		if (num_measurements == 0) {
			pcr++;
			continue;
		}

		status = pcr_lock (&store->pcrs[pcr]);
		if (status != 0) {
			return status;
		}

		status = pcr_compute (&store->pcrs[pcr], hash, false, NULL, 0);
		if (ROT_IS_ERROR (status)) {
			pcr_unlock (&store->pcrs[pcr]);
			return status;
		}

		digest_length = pcr_get_all_measurements (&store->pcrs[pcr], &measurements);

		switch (digest_length) {
			default:
				/* This isn't possible under normal conditions since invalid digest lengths would be
				 * rejected during init.  Fall through to SHA-256 in unexpected scenarios. */
			case SHA256_HASH_LENGTH:
				digest = log_entry.sha256.entry.digest;
				measurement_size = &log_entry.sha256.entry.measurement_size;
				measurement = log_entry.sha256.entry.measurement;
				entry_length = sizeof (log_entry.sha256);
				algorithm_id = PCR_TCG_SHA256_ALG_ID;
				break;

#if PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH
			case SHA384_HASH_LENGTH:
				digest = log_entry.sha384.entry.digest;
				measurement_size = &log_entry.sha384.entry.measurement_size;
				measurement = log_entry.sha384.entry.measurement;
				entry_length = sizeof (log_entry.sha384);
				algorithm_id = PCR_TCG_SHA384_ALG_ID;
				break;
#endif

#if PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH
			case SHA512_HASH_LENGTH:
				digest = log_entry.sha512.entry.digest;
				measurement_size = &log_entry.sha512.entry.measurement_size;
				measurement = log_entry.sha512.entry.measurement;
				entry_length = sizeof (log_entry.sha512);
				algorithm_id = PCR_TCG_SHA512_ALG_ID;
				break;
#endif
		}

		i = 0;
		while ((i < num_measurements) && (length > 0)) {
			log_entry.base.header.log_magic = LOGGING_MAGIC_START;
			log_entry.base.header.length = entry_length;
			log_entry.base.header.entry_id = entry_id++;

			log_entry.base.info.digest_algorithm_id = algorithm_id;
			log_entry.base.info.digest_count = 1;
			log_entry.base.info.event_type = measurements[i].event_type;
			log_entry.base.info.measurement_type = PCR_MEASUREMENT (pcr, i);

			*measurement_size = digest_length;
			memcpy (digest, measurements[i].digest, digest_length);
			memcpy (measurement, measurements[i].measurement, digest_length);

			entry_bytes = buffer_copy ((uint8_t*) &log_entry, entry_length, &offset, &length,
				contents);
			contents += entry_bytes;
			total_bytes += entry_bytes;

			i++;
		}

		pcr_unlock (&store->pcrs[pcr]);
		pcr++;
	}

	return total_bytes;
}

/**
 * Generate TCG formatted log for all measurements in the PCR store.
 *
 * Only data that will fit into the provided buffer will be returned.  Additional calls with
 * different length/offset values would be needed to get the remaining data.
 *
 * @param store The PCR store to query for log data.
 * @param offset Offset within the log to start reading data.
 * @param buffer Output buffer to populate with requested log contents.
 * @param length Maximum number of bytes to read from the log.
 *
 * @return The number of bytes read from the log or an error code.
 */
int pcr_store_get_tcg_log (struct pcr_store *store, size_t offset, uint8_t *buffer, size_t length)
{
	struct pcr_tcg_event v1_event;
	struct pcr_tcg_log_header header;
	size_t header_length;
	uint8_t algo_added = 0;
	size_t num_bytes = 0;
	size_t v1_length;
	size_t measurement_length;
	size_t i;
	int status;

	if ((store == NULL) || (buffer == NULL)) {
		return PCR_INVALID_ARGUMENT;
	}

	/* Construct the TCG log header.  The structure is variable length, depending on the total
	 * number of hash algorithms supported.  Clearing the entire structure will ensure
	 * vendor_info_size is always 0. */
	memset (&header, 0, sizeof (header));

	memcpy (header.signature, PCR_TCG_LOG_SIGNATURE, sizeof (header.signature));
	header.signature[15] = '\0';

	header.platform_class = PCR_TCG_SERVER_PLATFORM_CLASS;
	header.spec_version_minor = 0;
	header.spec_version_major = 2;
	header.spec_errata = 0;
	header.uintn_size = PCR_TCG_UINT_SIZE_32;

	/* Determine the set of unique hash algorithms used by all PCRs being managed. */
	for (i = 0; i < store->num_pcrs; i++) {
		switch (pcr_get_hash_algorithm (&store->pcrs[i])) {
			case HASH_TYPE_SHA256:
				if (!(algo_added & 0x1)) {
					header.digest_size[header.num_algorithms].digest_algorithm_id =
						PCR_TCG_SHA256_ALG_ID;
					header.digest_size[header.num_algorithms++].digest_size = SHA256_HASH_LENGTH;

					algo_added |= 0x1;
				}
				break;

#if PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH
			case HASH_TYPE_SHA384:
				if (!(algo_added & 0x2)) {
					header.digest_size[header.num_algorithms].digest_algorithm_id =
						PCR_TCG_SHA384_ALG_ID;
					header.digest_size[header.num_algorithms++].digest_size = SHA384_HASH_LENGTH;

					algo_added |= 0x2;
				}
				break;
#endif

#if PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH
			case HASH_TYPE_SHA512:
				if (!(algo_added & 0x4)) {
					header.digest_size[header.num_algorithms].digest_algorithm_id =
						PCR_TCG_SHA512_ALG_ID;
					header.digest_size[header.num_algorithms++].digest_size = SHA512_HASH_LENGTH;

					algo_added |= 0x4;
				}
				break;
#endif

			default:
				/* Not possible. */
				break;
		}
	}

	header_length = sizeof (struct pcr_tcg_log_header) - sizeof (header.digest_size) +
		(sizeof (header.digest_size[0]) * header.num_algorithms);

	/* Now that the header event length is known, construct the v1 event header for it. */
	v1_event.event_type = PCR_TCG_EFI_NO_ACTION_EVENT_TYPE;
	v1_event.event_size = header_length;
	v1_event.pcr_index = 0;

	memset (v1_event.digest, 0, sizeof (v1_event.digest));

	/* Add the v1 event header to the output buffer. */
	v1_length = buffer_copy ((uint8_t*) &v1_event, sizeof (v1_event), &offset, &length, buffer);
	num_bytes += v1_length;
	buffer += v1_length;

	/* Add the TCG log header to the v1 event. */
	v1_length = buffer_copy ((uint8_t*) &header, header_length, &offset, &length, buffer);
	num_bytes += v1_length;
	buffer += v1_length;

	/* Add measurements for each PCR. */
	i = 0;
	while ((i < store->num_pcrs) && (length > 0)) {
		status = pcr_get_tcg_log (&store->pcrs[i], i, offset, buffer, length, &measurement_length);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		if (status == 0) {
			offset -= measurement_length;
		}
		else {
			num_bytes += status;
			buffer += status;
			length -= status;
			offset = 0;
		}

		i++;
	}

	return num_bytes;
}
