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

int spdm_measurements_get_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type,
	uint8_t *buffer, size_t length)
{
	struct spdm_measurements_measurement_block *block =
		(struct spdm_measurements_measurement_block*) buffer;
	uint8_t *value = &buffer[sizeof (*block)];
	size_t max_length;
	enum pcr_dmtf_value_type value_type;
	int value_size;
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

	/* There needs to at least be enough room for the measurement block headers. */
	if (length < sizeof (struct spdm_measurements_measurement_block)) {
		return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
	}

	/* Since the measurement type comes from the PCR store, it's known to be good, meaning this call
	 * cannot fail. */
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

int spdm_measurements_get_measurement_block_length (const struct spdm_measurements *handler,
	uint8_t block_id)
{
	int measurement_type;

	measurement_type = spdm_measurements_get_measurement_type (handler, block_id);
	if (ROT_IS_ERROR (measurement_type)) {
		return measurement_type;
	}

	return spdm_measurements_get_bit_stream_length (handler, measurement_type);
}

int spdm_measurements_get_all_measurement_blocks (const struct spdm_measurements *handler,
	bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer,
	size_t length)
{
	return -1;
}

int spdm_measurements_get_all_measurement_blocks_length (const struct spdm_measurements *handler,
	bool raw_bit_stream, enum hash_type hash_type)
{
	return -1;
}

int spdm_measurements_get_measurement_summary (const struct spdm_measurements *handler,
	struct hash_engine *hash, enum hash_type measurement_hash_type,
	enum hash_type summary_hash_type, bool only_tcb, uint8_t *buffer, size_t length)
{
	return -1;
}

/**
 * Initialize a handler for retrieving SPDM measurements records for the device.
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
	handler->get_measurement_summary = spdm_measurements_get_measurement_summary;

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
