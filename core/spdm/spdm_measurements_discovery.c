// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "spdm_measurements_discovery.h"
#include "common/unused.h"


int spdm_measurements_discovery_get_measurement_count (const struct spdm_measurements *handler)
{
	if (handler == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	/* There is an extra measurement block for the discovery device ID. */
	return spdm_measurements_get_measurement_count (handler) + 1;
}

/**
 * Build the measurement block for the discovery device ID information.
 *
 * @param handler The measurement handler containing the device ID information.
 * @param raw_bit_stream Flag indicating if the raw device ID data should be returned.
 * @param hash Hash engine to use for calculating the measurement digest.
 * @param hash_type The hash algorithm to use for measurement digests.
 * @param buffer Output buffer for the device ID measurement block.
 * @param length Length of the measurement output buffer.
 *
 * @return The size of the constructed measurement block or an error code.
 */
static int spdm_measurements_discovery_build_device_id_block (
	const struct spdm_measurements *handler, bool raw_bit_stream, struct hash_engine *hash,
	enum hash_type hash_type, uint8_t *buffer, size_t length)
{
	const struct spdm_measurements_discovery *discovery =
		(const struct spdm_measurements_discovery*) handler;
	struct spdm_measurements_measurement_block *block =
		(struct spdm_measurements_measurement_block*) buffer;
	uint8_t *value = &buffer[sizeof (*block)];
	int value_size;
	size_t max_length;

	/* There needs to at least be enough room for the measurement block headers. */
	if (length < sizeof (struct spdm_measurements_measurement_block)) {
		return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
	}

	value_size = sizeof (*discovery->device_id);
	max_length = spdm_measurements_measurement_value_max_length (length);

	if (raw_bit_stream) {
		if (max_length < (size_t) value_size) {
			return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
		}

		memcpy (value, discovery->device_id, value_size);
	}
	else {
		value_size = hash_calculate (hash, hash_type, (uint8_t*) discovery->device_id, value_size,
			value, max_length);
		if (ROT_IS_ERROR (value_size)) {
			if (value_size == HASH_ENGINE_HASH_BUFFER_TOO_SMALL) {
				return SPDM_MEASUREMENTS_BUFFER_TOO_SMALL;
			}
			else {
				return value_size;
			}
		}
	}

	block->index = SPDM_DISCOVERY_DEVICE_ID_BLOCK_ID;
	block->measurement_specification = SPDM_MEASUREMENTS_DMTF_MEASUREMENT_SPEC_FORMAT;
	block->measurement_size = spdm_measurements_measurement_size (value_size);

	block->dmtf.raw_bit_stream = (raw_bit_stream) ? 1 : 0;
	block->dmtf.measurement_value_type = PCR_DMTF_VALUE_TYPE_HW_CONFIG;
	block->dmtf.measurement_value_size = value_size;

	return spdm_measurements_block_size (value_size);
}

int spdm_measurements_discovery_get_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type,
	uint8_t *buffer, size_t length)
{
	int status;

	status = spdm_measurements_get_measurement_block (handler, block_id, raw_bit_stream, hash,
		hash_type, buffer, length);

	/* Make the base call first to catch other parameter errors rather than needing to duplicate
	 * those checks here.  If the block ID is for the device ID measurement, build it here instead
	 * of failing the request. */
	if ((status == PCR_INVALID_SEQUENTIAL_ID) && (block_id == SPDM_DISCOVERY_DEVICE_ID_BLOCK_ID)) {
		status = spdm_measurements_discovery_build_device_id_block (handler, raw_bit_stream, hash,
			hash_type, buffer, length);
	}

	return status;
}

int spdm_measurements_discovery_get_measurement_block_length (
	const struct spdm_measurements *handler, uint8_t block_id)
{
	if (handler == NULL) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	if (block_id == SPDM_DISCOVERY_DEVICE_ID_BLOCK_ID) {
		return spdm_measurements_block_size (sizeof (struct spdm_discovery_device_id));
	}
	else {
		return spdm_measurements_get_measurement_block_length (handler, block_id);
	}
}

int spdm_measurements_discovery_get_all_measurement_blocks (const struct spdm_measurements *handler,
	bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer,
	size_t length)
{
	int record_length;
	int device_id_length;

	record_length = spdm_measurements_get_all_measurement_blocks (handler, raw_bit_stream, hash,
		hash_type, buffer, length);
	if (ROT_IS_ERROR (record_length)) {
		return record_length;
	}

	device_id_length = spdm_measurements_discovery_build_device_id_block (handler, raw_bit_stream,
		hash, hash_type, &buffer[record_length], length - record_length);
	if (ROT_IS_ERROR (device_id_length)) {
		return device_id_length;
	}

	return record_length + device_id_length;
}

int spdm_measurements_discovery_get_all_measurement_blocks_length (
	const struct spdm_measurements *handler, bool raw_bit_stream, enum hash_type hash_type)
{
	int record_length;

	record_length = spdm_measurements_get_all_measurement_blocks_length (handler, raw_bit_stream,
		hash_type);
	if (ROT_IS_ERROR (record_length)) {
		return record_length;
	}

	if (raw_bit_stream) {
		return record_length +
			   spdm_measurements_block_size (sizeof (struct spdm_discovery_device_id));
	}
	else {
		/* The hash type is known to be valid since the call to get length of all the other blocks
		 * succeeded. */
		return record_length + spdm_measurements_block_size (hash_get_hash_length (hash_type));
	}
}

int spdm_measurements_discovery_get_measurement_summary_hash (
	const struct spdm_measurements *handler, struct hash_engine *summary_hash,
	enum hash_type summary_hash_type, struct hash_engine *measurement_hash,
	enum hash_type measurement_hash_type, bool only_tcb, uint8_t *buffer, size_t length)
{
	uint8_t block[spdm_measurements_block_size (HASH_MAX_HASH_LEN)];
	int block_size;
	int status;

	status = spdm_measurements_start_summary_hash (handler, summary_hash, summary_hash_type,
		measurement_hash, buffer, length);
	if (status != 0) {
		return status;
	}

	status = spdm_measurements_update_summary_hash (handler, summary_hash, measurement_hash,
		measurement_hash_type, only_tcb);
	if (status != 0) {
		goto exit;
	}

	/* The device ID measurement block is not part of the TCB. */
	if (!only_tcb) {
		block_size = spdm_measurements_discovery_build_device_id_block (handler, false,
			measurement_hash, measurement_hash_type, block, sizeof (block));
		if (ROT_IS_ERROR (block_size)) {
			status = block_size;
			goto exit;
		}

		status = summary_hash->update (summary_hash, block, block_size);
		if (status != 0) {
			goto exit;
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
 * Initialize a handler for retrieving SPDM measurement records for the device.  The device supports
 * reporting a device ID measurement block useful for attestation discovery.
 *
 * Reporting the device ID measurement is only compatible with SPDM version 1.2 or later.
 *
 * @param handler The SPDM measurement handler to initialize.
 * @param store The measurement storage containing the data to report in measurement records.
 * @param device_id The measurement bit stream to report for the device ID block ID.
 *
 * @return 0 if the measurement handler was initialized successfully or an error code.
 */
int spdm_measurements_discovery_init (struct spdm_measurements_discovery *handler,
	struct pcr_store *store, const struct spdm_discovery_device_id *device_id)
{
	if ((handler == NULL) || (store == NULL) || (device_id == NULL)) {
		return SPDM_MEASUREMENTS_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct spdm_measurements_discovery));

	handler->base.get_measurement_count = spdm_measurements_discovery_get_measurement_count;
	handler->base.get_measurement_block = spdm_measurements_discovery_get_measurement_block;
	handler->base.get_measurement_block_length =
		spdm_measurements_discovery_get_measurement_block_length;
	handler->base.get_all_measurement_blocks =
		spdm_measurements_discovery_get_all_measurement_blocks;
	handler->base.get_all_measurement_blocks_length =
		spdm_measurements_discovery_get_all_measurement_blocks_length;
	handler->base.get_measurement_summary_hash =
		spdm_measurements_discovery_get_measurement_summary_hash;

	handler->base.store = store;
	handler->device_id = device_id;

	return 0;
}

/**
 * Release the resources used for SPDM measurement handing with support for discovery.
 *
 * @param handler The SPDM measurement handler to release.
 */
void spdm_measurements_discovery_release (const struct spdm_measurements_discovery *handler)
{
	UNUSED (handler);
}
