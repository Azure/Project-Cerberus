// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>



/**
 * Get the number of bits set in a byte before specified bit index
 *
 * @param byte Byte to check
 * @param index Bit index
 *
 * @return Number of bits set in received byte
 */
int common_math_get_num_bits_set_before_index (uint8_t byte, uint8_t index)
{
	int num_bits = 0;

	while ((byte != 0) && (index !=0)) {
		if (byte & 0x01) {
			++num_bits;
		}

		byte >>= 1;
		index--;
	}

	return num_bits;
}

/**
 * Get the number of bits set in a byte
 *
 * @param byte Byte to check
 *
 * @return Number of bits set in received byte
 */
int common_math_get_num_bits_set (uint8_t byte)
{
	return common_math_get_num_bits_set_before_index (byte, 8);
}


