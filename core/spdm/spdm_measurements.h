// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_MEASUREMENTS_H_
#define SPDM_MEASUREMENTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "attestation/pcr_store.h"
#include "crypto/hash.h"
#include "status/rot_status.h"


#pragma pack(push, 1)
/**
 * Header for a measurement portion of measurement block following DMTF format.  Defined in the SPDM
 * DSP0274 spec section 10.11.1.1.
 */
struct spdm_measurements_dmtf_measurement {
	uint8_t measurement_value_type:7;	/**< The type of data being reported in the measurement. */
	uint8_t raw_bit_stream:1;			/**< Flag indicating whether data is in raw or digest form. */
	uint16_t measurement_value_size;	/**< The size of the measurement data. */
};

/**
 * Header for a SPDM measurement block.  SPDM currently only defines the DMTF format as a valid
 * measurement specification, so this format is assumed by the structure definition.  Defined  in
 * the SPDM DSP0274 spec section 10.11.1.
 */
struct spdm_measurements_measurement_block {
	uint8_t index;									/**< Measurement block index. */
	uint8_t measurement_specification;				/**< Measurement specification the measurement block format follows. */
	uint16_t measurement_size;						/**< Total size of the DMTF wrapped measurement data. */
	struct spdm_measurements_dmtf_measurement dmtf;	/**< Measurement data following the DMTF format. */
};

/**
 * Measurement specification identifier indicating that the measurement follows the DMTF measurement
 * specification format.
 */
#define SPDM_MEASUREMENTS_DMTF_MEASUREMENT_SPEC_FORMAT			(1 << 0)

/**
 * Get a pointer to the measurement value data contained in a measurement block.
 *
 * @param block Pointer to a SPDM measurement block.
 */
#define spdm_measurements_measurement_value(block)      \
	(uint8_t*) (((uint8_t*) block) + sizeof (struct spdm_measurements_measurement_block))

/**
 * Get the maximum length possible for the measurement value in a measurement block.
 *
 * @param length Total length of the measurement block buffer.
 */
#define spdm_measurements_measurement_value_max_length(length) \
	((length) - sizeof (struct spdm_measurements_measurement_block))

/**
 * Get the total length of a SPDM measurement block containing a DMTF formatted measurement,
 * including all headers.
 *
 * @param measurement_value_size Size of measurement data contained in the measurement block.
 */
#define spdm_measurements_block_size(measurement_value_size)        \
	(sizeof (struct spdm_measurements_measurement_block) + measurement_value_size)

/**
 * Get the total length of a measurement following the DMTF measurement specification format,
 * including the header.
 *
 * @param measurement_value_size Size of measurement data contained in the measurement block.
 */
#define spdm_measurements_measurement_size(measurement_value_size)  \
	(sizeof (struct spdm_measurements_dmtf_measurement) + measurement_value_size)
#pragma pack(pop)


/**
 * Handler for retrieving SPDM measurement records for device measurements.
 */
struct spdm_measurements {
	/**
	 * Get the total number of measurements supported by the device.
	 *
	 * @param handler The measurement handler to query.
	 *
	 * @return The total number of device measurements or an error code.  Use ROT_IS_ERROR to check
	 * the return value.
	 */
	int (*get_measurement_count) (const struct spdm_measurements *handler);

	/**
	 * Get the data for a single measurement block provided by the device.  The requested
	 * measurement data will be wrapped as a properly formatted SPDM measurement block following the
	 * DMTF measurement specification.
	 *
	 * @param handler The measurement handler to query.
	 * @param block_id The block ID for the measurement to retrieve.  Valid values are between 0x01
	 * and the total number of supported measurements, inclusive.
	 * @param raw_bit_stream Flag indicating that raw measurement data is being requested.
	 * @param hash Hash engine to use for calculating the hash of the measurement data.  This is
	 * only necessary when not requesting the raw bit stream.
	 * @param hash_type The hash algorithm to use for calculating the measurement hash.
	 * @param buffer Output buffer for the measurement block data.
	 * @param length The size of the output buffer.
	 *
	 * @return The total number of bytes written to the output buffer or an error code.  Use
	 * ROT_IS_ERROR to check the return value.
	 * - If the raw bit stream is requested but cannot be provided,
	 *   SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE will be returned.
	 * - If the raw bit stream is not requested but hashing the measurement is not allowed,
	 *   SPDM_MEASUREMENTS_HASH_NOT_APPLICABLE will be returned.
	 * - If the measurement hash cannot be calculated, SPDM_MEASUREMENTS_HASH_NOT_POSSIBLE will be
	 *   returned.
	 */
	int (*get_measurement_block) (const struct spdm_measurements *handler, uint8_t block_id,
		bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer,
		size_t length);

	/**
	 * Get the total data length for a single measurement block.  This length will include the
	 * measurement block header and the raw bit stream for the measurement.
	 *
	 * @param handler The measurement handler to query.
	 * @param block_id The block ID for the measurement to query.  Valid values are between 0x01 and
	 * the total number of supported measurements, inclusive.
	 *
	 * @return The total data length for the measurement block or an error code.  Use ROT_IS_ERROR
	 * to check the return value.  If the raw bit stream for the measurement cannot be provided,
	 * SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE will be returned.
	 */
	int (*get_measurement_block_length) (const struct spdm_measurements *handler, uint8_t block_id);

	/**
	 * Get a measurement record that contains all the measurements supported by the device.  Each
	 * individual measurement will be wrapped as a properly formatted SPDM measurement block
	 * following the DMTF measurement specification.
	 *
	 * @param handler The measurement handler to query.
	 * @param raw_bit_stream Flag indicating that raw measurements are being requested.  This does
	 * not guarantee that all measurements will have the raw data returned.  Any measurements that
	 * do not have the raw bit stream available will return the measurement hash instead.  Also, any
	 * measurements that don't support hashing will always return the raw bit stream.
	 * @param hash Hash engine to use for calculating the hash of measurement data.  This must
	 * always be provided, regardless of whether raw bit stream is being requested or not.
	 * @param hash_type The hash algorithm to use for calculating measurement hashes.
	 * @param buffer Output buffer for the measurement record.
	 * @param length The size of the output buffer.
	 *
	 * @return The total number of bytes written to the output buffer or an error code.  Use
	 * ROT_IS_ERROR to check the return value.  If any measurement requires a hash calculation that
	 * cannot be performed, SPDM_MEASUREMENTS_HASH_NOT_POSSIBLE will be returned.
	 */
	int (*get_all_measurement_blocks) (const struct spdm_measurements *handler, bool raw_bit_stream,
		struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer, size_t length);

	/**
	 * Get the total length for a measurement record that contains all measurements supported by the
	 * device.
	 *
	 * @param handler The measurement handler to query.
	 * @param raw_bit_stream Flag indicating if the length calculation should be performed for a
	 * measurement record containing raw bit stream data (true) or measurement hashes (false).
	 * @param hash_type The hash algorithm that would be used for any measurement hashes.  Even if
	 * raw bit stream is requested, some measurements may still require reporting a hash.
	 *
	 * @return The total data length of the measurement record or an error code.
	 */
	int (*get_all_measurement_blocks_length) (const struct spdm_measurements *handler,
		bool raw_bit_stream, enum hash_type hash_type);

	/**
	 * Generate an SPDM measurement summary hash of the device measurements.
	 *
	 * @param handler The measurement handler that will generate the summary hash.
	 * @param summary_hash Hash engine to use for summary hash calculation.
	 * @param summary_hash_type The hash algorithm to use for calculating the measurement summary
	 * hash.
	 * @param measurement_hash Hash engine to use for measurement hash calculation.  This must be a
	 * different hash engine from the one used for the summary hash calculation.
	 * @param measurement_hash_type The hash algorithm to use for calculating each individual
	 * measurement hash included in the summary hash.
	 * @param only_tcb Flag indicating if only measurements that are part of the device's Trusted
	 * Computing Base (TCB) should be included in the summary hash.
	 * @param buffer Output buffer for the measurement summary hash.
	 * @param length The size of the output buffer.
	 *
	 * @param 0 if summary hash was generated successfully or an error code.  The hash length is
	 * determined by the summary hash algorithm.
	 */
	int (*get_measurement_summary_hash) (const struct spdm_measurements *handler,
		struct hash_engine *summary_hash, enum hash_type summary_hash_type,
		struct hash_engine *measurement_hash, enum hash_type measurement_hash_type, bool only_tcb,
		uint8_t *buffer, size_t length);

	struct pcr_store *store;	/**< Device measurement management. */
};


int spdm_measurements_init (struct spdm_measurements *handler, struct pcr_store *store);
void spdm_measurements_release (const struct spdm_measurements *handler);

/* Internal functions for use by derived types. */
int spdm_measurements_get_measurement_count (const struct spdm_measurements *handler);
int spdm_measurements_get_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type,
	uint8_t *buffer, size_t length);
int spdm_measurements_get_measurement_block_length (const struct spdm_measurements *handler,
	uint8_t block_id);

int spdm_measurements_get_all_measurement_blocks (const struct spdm_measurements *handler,
	bool raw_bit_stream, struct hash_engine *hash, enum hash_type hash_type, uint8_t *buffer,
	size_t length);
int spdm_measurements_get_all_measurement_blocks_length (const struct spdm_measurements *handler,
	bool raw_bit_stream, enum hash_type hash_type);

int spdm_measurements_start_summary_hash (const struct spdm_measurements *handler,
	struct hash_engine *summary_hash, enum hash_type summary_hash_type,
	struct hash_engine *measurement_hash, uint8_t *buffer, size_t length);
int spdm_measurements_update_summary_hash (const struct spdm_measurements *handler,
	struct hash_engine *summary_hash, struct hash_engine *measurement_hash,
	enum hash_type measurement_hash_type, bool only_tcb);


#define	SPDM_MEASUREMENTS_ERROR(code)		ROT_ERROR (ROT_MODULE_SPDM_MEASUREMENTS, code)

/**
 * Error codes that can be generated by a SPDM measurements handler.
 */
enum {
	SPDM_MEASUREMENTS_INVALID_ARGUMENT = SPDM_MEASUREMENTS_ERROR (0x00),				/**< Input parameter is null or not valid. */
	SPDM_MEASUREMENTS_NO_MEMORY = SPDM_MEASUREMENTS_ERROR (0x01),						/**< Memory allocation failed. */
	SPDM_MEASUREMENTS_GET_COUNT_FAILED = SPDM_MEASUREMENTS_ERROR (0x02),				/**< Failed to determine the number of measurements. */
	SPDM_MEASUREMENTS_GET_BLOCK_FAILED = SPDM_MEASUREMENTS_ERROR (0x03),				/**< Failed to get a measurement block. */
	SPDM_MEASUREMENTS_BLOCK_LENGTH_FAILED = SPDM_MEASUREMENTS_ERROR (0x04),				/**< Failed to determine a measurement block length. */
	SPDM_MEASUREMENTS_GET_ALL_BLOCKS_FAILED = SPDM_MEASUREMENTS_ERROR (0x05),			/**< Failed to get all measurement blocks. */
	SPDM_MEASUREMENTS_ALL_BLOCKS_LENGTH_FAILED = SPDM_MEASUREMENTS_ERROR (0x06),		/**< Failed to determine the length of all blocks. */
	SPDM_MEASUREMENTS_GET_SUMMARY_FAILED = SPDM_MEASUREMENTS_ERROR (0x07),				/**< Failed to get the measurement summary hash. */
	SPDM_MEASUREMENTS_RAW_BIT_STREAM_NOT_AVAILABLE = SPDM_MEASUREMENTS_ERROR (0x08),	/**< The raw bit stream for the measurement is not available. */
	SPDM_MEASUREMENTS_HASH_NOT_APPLICABLE = SPDM_MEASUREMENTS_ERROR (0x09),				/**< Returning the hash of the measurement is not allowed. */
	SPDM_MEASUREMENTS_HASH_NOT_POSSIBLE = SPDM_MEASUREMENTS_ERROR (0x0a),				/**< It's not possible to hash the measurement with the requested algorithm. */
	SPDM_MEASUREMENTS_BUFFER_TOO_SMALL = SPDM_MEASUREMENTS_ERROR (0x0b),				/**< The output buffer is not large enough for the measurement record. */
	SPDM_MEASUREMENTS_RESERVED_BLOCK_ID = SPDM_MEASUREMENTS_ERROR (0x0c),				/**< The request uses a reserved block ID. */
	SPDM_MEASUREMENTS_SAME_HASH_ENGINE = SPDM_MEASUREMENTS_ERROR (0x0d),				/**< Non-unique hash engines have been provided. */
};


#endif	/* SPDM_MEASUREMENTS_H_ */
