// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_MEASUREMENTS_STATIC_H_
#define SPDM_MEASUREMENTS_STATIC_H_

#include "spdm_measurements.h"


/* Internal function declarations to allow for static initialization. */
int spdm_measurements_get_measurement_summary_hash (const struct spdm_measurements *handler,
	struct hash_engine *summary_hash, enum hash_type summary_hash_type,
	struct hash_engine *measurement_hash, enum hash_type measurement_hash_type, bool only_tcb,
	uint8_t *buffer, size_t length);


/**
 * Constant initializer for the SPDM measurements API.
 */
#define	SPDM_MEASUREMENTS_API_INIT	\
	.get_measurement_count = spdm_measurements_get_measurement_count, \
	.get_measurement_block = spdm_measurements_get_measurement_block, \
	.get_measurement_block_length = spdm_measurements_get_measurement_block_length, \
	.get_all_measurement_blocks = spdm_measurements_get_all_measurement_blocks, \
	.get_all_measurement_blocks_length = spdm_measurements_get_all_measurement_blocks_length, \
	.get_measurement_summary_hash = spdm_measurements_get_measurement_summary_hash


/**
 * Initialize a static instance of a handler for retrieving SPDM measurement records for the device.
 *
 * There is no validation done on the arguments.
 *
 * @param store_ptr The measurement storage containing the data to report in measurement records.
 */
#define	spdm_measurements_static_init(store_ptr)	{ \
		SPDM_MEASUREMENTS_API_INIT, \
		.store = store_ptr, \
	}


#endif /* SPDM_MEASUREMENTS_STATIC_H_ */
