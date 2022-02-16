// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include "checksum.h"

/**
 * Compute CRC8 value of data buffer
 *
 * @param smbus_addr SMBUS address to prepend to buffer before computation
 * @param data Data buffer to use for CRC calculation
 * @param len Length of data buffer
 *
 * @return CRC8 value
 */
uint8_t checksum_crc8 (uint8_t smbus_addr, const uint8_t *data, uint8_t len)
{
	uint8_t crc;

	if ((data == NULL) || (len == 0)) {
		return 0;
	}

	crc = checksum_init_smbus_crc8 (smbus_addr);
	return checksum_update_smbus_crc8 (crc, data, len);
}

/**
 * Initialize an SMBus CRC8 calculation.
 *
 * @param smbus_addr SMBus address of the target device.
 *
 * @return The intermediate CRC8 value that can be extended with additional data.
 */
uint8_t checksum_init_smbus_crc8 (uint8_t smbus_addr)
{
	return checksum_update_smbus_crc8 (0, &smbus_addr, 1);
}

/**
 * Continue an SMBus CRC8 calculation.
 *
 * @param crc The initial CRC8 value to use for the calculation.
 * @param data Buffer that contains the data to use for the calculation.
 * @param len The number of bytes in the buffer.
 *
 * @return The resulting CRC8.  This can used as the initial CRC value is subsequent operations, if
 * necessary.
 */
uint8_t checksum_update_smbus_crc8 (uint8_t crc, const uint8_t *data, uint8_t len)
{
	int i;
	int j;

	if (data == NULL) {
		return crc;
	}

	for (i = 0; i < len; ++i) {
		crc ^= data[i];

		for (j = 0; j < 8; ++j) {
			if ((crc & 0x80) != 0) {
				crc = (uint8_t) ((crc << 1) ^ 0x07);
			}
			else {
				crc <<= 1;
			}
		}
	}

	return crc;
}
