// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCR_DATA_H_
#define PCR_DATA_H_

#include <stdint.h>
#include "crypto/hash.h"
#include "flash/flash.h"


/**
 * Measured PCR data type
 */
enum pcr_data_type {
	PCR_DATA_TYPE_1BYTE,	/**< 1 byte long PCR data */
	PCR_DATA_TYPE_2BYTE,	/**< 2 bytes long PCR data */
	PCR_DATA_TYPE_4BYTE,	/**< 4 bytes long PCR data */
	PCR_DATA_TYPE_8BYTE,	/**< 8 bytes long PCR data */
	PCR_DATA_TYPE_MEMORY,	/**< PCR data stored in memory buffer */
	PCR_DATA_TYPE_FLASH,	/**< PCR data stored in a flash device */
	PCR_DATA_TYPE_CALLBACK,	/**< PCR data retrieved by callback */
	NUM_PCR_DATA_TYPE,		/**< Number of PCR data types supported */
};


/**
 * Get the measured data.
 *
 * @param context The context to query for measured data.
 * @param offset The offset to read data from.
 * @param buffer Output buffer to be filled in with measured data.
 * @param length Maximum length of the buffer.
 * @param total_len Output buffer containing the total length of the measurement data. This should
 * 	contain total length of the measured data even if only partially returned.
 *
 * @return The length of the measured data if successfully read or an error code.
 */
typedef int (*pcr_data_get_measured_data) (void *context, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len);

/**
 * Update a hash context with the measured data.
 *
 * The hash context will already be started and it must not be canceled or finished by the callback.
 *
 * @param context The context that will update the hash with the measured data.
 * @param hash Hash engine that will be updated with the data.
 *
 * @return 0 if the hash was successfully updated or an error code.
 */
typedef int (*pcr_data_hash_measured_data) (void *context, struct hash_engine *hash);

/**
 * Measurement data used for PCR measurement.
 */
struct pcr_measured_data {
	enum pcr_data_type type;						/**< Measured data type */

	union {
		uint8_t value_1byte;						/**< Value for 1 byte measured data type */
		uint16_t value_2byte;						/**< Value for 2 bytes measured data type */
		uint32_t value_4byte;						/**< Value for 4 bytes measured data type */
		uint64_t value_8byte;						/**< Value for 8 bytes measured data type */

		struct {
			const uint8_t *buffer;					/**< Buffer containing the measured data */
			size_t length;							/**< Buffer length */
		} memory;									/**< Container for measured data stored in memory */

		struct  {
			const struct flash *flash;				/**< Flash device containing the measured data */
			uint32_t addr;							/**< Address in flash */
			size_t length;							/**< Measured data length */
		} flash;									/**< Container for measured data stored in flash */

		struct  {
			pcr_data_get_measured_data get_data;	/**< Callback function to get measured data */
			pcr_data_hash_measured_data hash_data;	/**< Callback function to hash the measured data */
			void *context;							/**< Context for the callback function */
		} callback;									/**< Container for measured data to be retrieved by callback function */
	} data;											/**< Measured data container */
};


#endif	/* PCR_DATA_H_ */
