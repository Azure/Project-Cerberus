// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "spdm_measurements.h"
#include "common/unused.h"


int spdm_measurements_get_measurement_count (const struct spdm_measurements *handler)
{
	if (handler == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	return pcr_store_get_num_total_measurements (handler->store);
}

/**
 * Determine the measurement identifier to use with PCR handler for a specific block ID.
 *
 * @param handler The SPDM measurement handler running the translation.
 * @param block_id The SPDM measurement block ID to translate.
 *
 * @return The PCR measurement identifier or an error code.
 */
static int spdm_measurements_get_measurement_type (const struct spdm_measurements *handler,
	uint8_t block_id)
{
	if (handler == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	/* Reject requests for special-case block IDs. */
	if ((block_id == 0) || (block_id == 0xff)) {
		return SPDM_MEASUREMENTS_RESERVED_BLOCK_ID;
	}

	return pcr_store_get_measurement_type (handler->store, block_id - 1);
}

/**
 * Get the total length for the raw bit stream of a single measurement.
 *
 * @param handler The SPDM measurement handler to query.
 * @param measurement_type The measurement identifier being checked.
 *
 * @return The total raw bit stream length or an error code.
 */
static int spdm_measurements_get_bit_stream_length (const struct spdm_measurements *handler,
	uint16_t measurement_type)
{
	int value_size;

	value_size = pcr_store_get_measurement_data_length (handler->store, measurement_type);
	if (value_size == PCR_MEASURED_DATA_NOT_AVIALABLE) {
		value_size = SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE;
	}

	return value_size;
}

/**
 * Construct an SPDM measurement block for a single device measurement.
 *
 * @param handler The handler to use for constructing the measurement block.
 * @param block_id The ID of the measurement block to construct.
 * @param measurement_type Identifier in the measurement storage for the measurement data.  This
 * must be a known good value.
 * @param raw_bit_stream Flag indicating that the raw measurement data should be populated in the
 * measurement block.
 * @param hash Hash engine to use for generating measurement digests.
 * @param hash_type The hash algorithm to use for for measurement digests.
 * @param buffer Output buffer for the measurement block.
 * @param length Length of the output buffer.  If this isn't large enough to hold the full
 * measurement block, the call will fail.  There m
 *
 * @return The number of bytes written to the output buffer or an error code.
 */
static int spdm_measurements_build_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, uint16_t measurement_type, bool raw_bit_stream, struct hash_engine *hash,
	enum hash_type hash_type, uint8_t *buffer, size_t length)
{
	struct spdm_measurements_measurement_block *block =
		(struct spdm_measurements_measurement_block*) buffer;
	uint8_t *value = &buffer[sizeof (*block)];
	size_t max_length;
	enum pcr_dmtf_value_type value_type;
	int value_size;

	/* There needs to at least be enough room for the measurement block headers. */
	if (length < sizeof (struct spdm_measurements_measurement_block)) {
		return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
	}

	/* The caller is responsible for ensuring a valid measurement type, which means this call will
	 * not fail. */
	pcr_store_get_dmtf_value_type (handler->store, measurement_type, &value_type);

	max_length = spdm_measurements_measurement_value_max_length (length);
	if (raw_bit_stream) {
		value_size = spdm_measurements_get_bit_stream_length (handler, measurement_type);
		if (ROT_IS_ERROR (value_size)) {
			return value_size;
		}

		/* Fail if there is not enough room for the entire bit stream.
		 *
		 * TODO:  Define a separate API and infrastructure to support chunking large measurement bit
		 * streams.  Perhaps a scheme that returns a chunking context that would then execute a
		 * series of offset/length requests on the bit stream data. */
		if ((size_t) value_size > max_length) {
			return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
		}

		value_size = pcr_store_get_measurement_data (handler->store, measurement_type, 0, value,
			max_length);
		if (ROT_IS_ERROR (value_size)) {
			return value_size;
		}
	}
	else {
		value_size = pcr_store_hash_measurement_data (handler->store, measurement_type, hash,
			hash_type, value, max_length);
		if (ROT_IS_ERROR (value_size)) {
			if (value_size == PCR_SMALL_OUTPUT_BUFFER) {
				return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
			}
			else if (value_size == PCR_MEASURED_DATA_NOT_AVIALABLE) {
				return SPDM_MEASUREMENTS_HASH_NOT_POSSIBLE;
			}
			else {
				return value_size;
			}
		}
	}

	block->index = block_id;
	block->measurement_specification = SPDM_MEASUREMENTS_DMTF_MEASUREMENT_SPEC_FORMAT;
	block->measurement_size = spdm_measurements_measurement_size (value_size);

	block->dmtf.raw_bit_stream = (raw_bit_stream) ? 1 : 0;
	block->dmtf.measurement_value_type = value_type;
	block->dmtf.measurement_value_size = value_size;

	return spdm_measurements_block_size (value_size);
}

int spdm_measurements_get_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type,
	uint8_t *buffer, size_t length)
{
	int measurement_type;

	if (buffer == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	if (!raw_bit_stream && (hash == NULL)) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	measurement_type = spdm_measurements_get_measurement_type (handler, block_id);
	if (ROT_IS_ERROR (measurement_type)) {
		return measurement_type;
	}

	return spdm_measurements_build_measurement_block (handler, block_id, measurement_type,
		raw_bit_stream, hash, hash_type, buffer, length);
}

int spdm_measurements_get_measurement_block_length (const struct spdm_measurements *handler,
	uint8_t block_id)
{
	int measurement_type;
	int value_size;

	measurement_type = spdm_measurements_get_measurement_type (handler, block_id);
	if (ROT_IS_ERROR (measurement_type)) {
		return measurement_type;
	}

	value_size = spdm_measurements_get_bit_stream_length (handler, measurement_type);
	if (ROT_IS_ERROR (value_size)) {
		return value_size;
	}

	return spdm_measurements_block_size (value_size);
}

int spdm_measurements_get_all_measurement_blocks (const struct spdm_measurements *handler,
	bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer,
	size_t length)
{
	size_t total_length = 0;
	int bytes;
	int pcr_count;
	int measurement_count;
	int i;
	int j;
	uint8_t block_id;
	uint16_t measurement_type;

	if ((handler == NULL) || (hash == NULL) || (buffer == NULL)) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	pcr_count = pcr_store_get_num_pcrs (handler->store);

	for (i = 0, block_id = 1; i < pcr_count; i++) {
		measurement_count = pcr_store_get_num_pcr_measurements (handler->store, i);

		for (j = 0; j < measurement_count; j++, block_id++) {
			/* The measurement type is constructed based on values reported from the PCR store, so
			 * it will always be valid. */
			measurement_type = PCR_MEASUREMENT (i, j);

			bytes = spdm_measurements_build_measurement_block (handler, block_id, measurement_type,
				raw_bit_stream, hash, hash_type, &buffer[total_length], length - total_length);
			if (bytes == SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE) {
				/* Getting the raw bit stream is not possible for this measurement, so try to get
				 * the digest instead. */
				bytes = spdm_measurements_build_measurement_block (handler, block_id,
					measurement_type, false, hash, hash_type, &buffer[total_length],
					length - total_length);
			}
			if (ROT_IS_ERROR (bytes)) {
				return bytes;
			}

			total_length += bytes;
		}
	}

	return total_length;
}

int spdm_measurements_get_all_measurement_blocks_length (const struct spdm_measurements *handler,
	bool raw_bit_stream, enum hash_type hash_type)
{
	int hash_length;
	size_t total_length = 0;
	int bytes;
	int pcr_count;
	int measurement_count;
	int i;
	int j;
	uint16_t measurement_type;

	if (handler == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	hash_length = hash_get_hash_length (hash_type);
	if (hash_length == HASH_ENGINE_UNKNOWN_HASH) {
		return hash_length;
	}

	pcr_count = pcr_store_get_num_pcrs (handler->store);

	for (i = 0; i < pcr_count; i++) {
		measurement_count = pcr_store_get_num_pcr_measurements (handler->store, i);

		for (j = 0; j < measurement_count; j++) {
			measurement_type = PCR_MEASUREMENT (i, j);

			if (raw_bit_stream) {
				bytes = spdm_measurements_get_bit_stream_length (handler, measurement_type);
				if (ROT_IS_ERROR (bytes)) {
					if (bytes == SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE) {
						bytes = hash_length;
					}
					else {
						return bytes;
					}
				}
			}
			else {
				bytes = hash_length;
			}

			total_length += spdm_measurements_block_size (bytes);
		}
	}

	return total_length;
}

int spdm_measurements_get_measurement_summary_hash (const struct spdm_measurements *handler,
	struct hash_engine *summary_hash, enum hash_type summary_hash_type,
	struct hash_engine *measurement_hash, enum hash_type measurement_hash_type, bool only_tcb,
	uint8_t *buffer, size_t length)
{
	uint8_t block[spdm_measurements_block_size (HASH_MAX_HASH_LEN)];
	int block_size;
	int pcr_count;
	int measurement_count;
	int i;
	int j;
	uint8_t block_id;
	uint16_t measurement_type;
	int status;

	if ((handler == NULL) || (summary_hash == NULL) || (measurement_hash == NULL) ||
		(buffer == NULL)) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	/* This operation requires unique hash engine instances to function correctly. */
	if (summary_hash == measurement_hash) {
		return SPDM_MEASUREMENTS_SAME_HASH_ENGINE;
	}

	status = hash_start_new_hash (summary_hash, summary_hash_type);
	if (status != 0) {
		return status;
	}

	/* Do a quick check of the output buffer length before starting the expensive summary hash
	 * operation.  Since the hash started successfully, the hash type is known to be good. */
	if (length < (size_t) hash_get_hash_length (summary_hash_type)) {
		status = SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
		goto exit;
	}

	pcr_count = pcr_store_get_num_pcrs (handler->store);

	for (i = 0, block_id = 1; i < pcr_count; i++) {
		measurement_count = pcr_store_get_num_pcr_measurements (handler->store, i);

		for (j = 0; j < measurement_count; j++, block_id++) {
			/* The measurement type is constructed based on values reported from the PCR store, so
			 * it will always be valid. */
			measurement_type = PCR_MEASUREMENT (i, j);

			if (!only_tcb || pcr_store_is_measurement_in_tcb (handler->store, measurement_type)) {
				block_size = spdm_measurements_build_measurement_block (handler, block_id,
					measurement_type, false, measurement_hash, measurement_hash_type, block,
					sizeof (block));
				if (ROT_IS_ERROR (block_size)) {
					status = block_size;
					goto exit;
				}

				status = summary_hash->update (summary_hash, block, block_size);
				if (status != 0) {
					goto exit;
				}
			}
		}
	}

	status = summary_hash->finish (summary_hash, buffer, length);

exit:
	if (status != 0) {
		summary_hash->cancel (summary_hash);
	}
	return status;
}

/**
 * Initialize a handler for retrieving SPDM measurement records for the device.
 *
 * @param handler The SPDM measurement handler to initialize.
 * @param store The measurement storage containing the data to report in measurement records.
 *
 * @return 0 if the measurement handler was initialized successfully or an error code.
 */
int spdm_measurements_init (struct spdm_measurements *handler, struct pcr_store *store)
{
	if ((handler == NULL) || (store == NULL)) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct spdm_measurements));

	handler->get_measurement_count = spdm_measurements_get_measurement_count;
	handler->get_measurement_block = spdm_measurements_get_measurement_block;
	handler->get_measurement_block_length = spdm_measurements_get_measurement_block_length;
	handler->get_all_measurement_blocks = spdm_measurements_get_all_measurement_blocks;
	handler->get_all_measurement_blocks_length =
		spdm_measurements_get_all_measurement_blocks_length;
	handler->get_measurement_summary_hash = spdm_measurements_get_measurement_summary_hash;

	handler->store = store;

	return 0;
}

/**
 * Release the resources used for SPDM measurement handing.
 *
 * @param handler The SPDM measurement handler to release.
 */
void spdm_measurements_release (const struct spdm_measurements *handler)
{
	UNUSED (handler);
}
