// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include "checksum.h"

/**
 * Compute CRC8 value of data buffer
 * Implementation based on: http://www.sunshine2k.de/articles/coding/crc/understanding_crc.html
 *
 * @param smbus_addr SMBUS address to prepend to buffer before computation
 * @param data Data buffer to compute CRC of
 * @param len Length of data buffer
 *
 * @return CRC8 value
 */
uint8_t checksum_crc8 (uint8_t smbus_addr, uint8_t *data, uint8_t len)
{
	uint8_t i;
	uint8_t j;
	uint8_t crc = 0;

	if ((data == NULL) || (len == 0)){
		return 0;
	}

	crc ^= smbus_addr;

	for (j = 0; j < 8; ++j) {
		if ((crc & 0x80) != 0) {
			crc = (uint8_t) ((crc << 1) ^ 0x07);
		}
		else {
			crc <<= 1;
		}
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
