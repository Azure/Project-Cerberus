// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>


/**
 * Get the number of bits set in a byte
 *
 * @param byte Byte to check
 *
 * @return Number of bits set in received byte
 */
int common_math_get_num_bits_set (uint8_t byte)
{
	int num_bits = 0;

	while (byte != 0) {
		if (byte & 0x01) {
			++num_bits;
		}

		byte >>= 1;
	}

	return num_bits;
}
