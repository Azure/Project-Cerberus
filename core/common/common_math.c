// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "common_math.h"



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

/**
 * Increments byte array of arbitary length len by 1
 *
 * @param len length of the array
 * @param buf input array to be incremented
 * @param allow_rollover lets to roll over when upper boundary is reached
 *
 * @return 0 if the input array is incremented successfully
 */
int common_math_increment_byte_array (uint8_t *buf, size_t length, bool allow_rollover)
{
	size_t index = 0;

	if ((length == 0) || (buf == NULL)) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	while ((index < (length - 1)) && (buf[index] == 0xff)) {
		buf[index++] = 0;
	}

	if ((index == (length - 1)) && (buf[index] == 0xff)) {
		if (allow_rollover) {
			buf[index] = 0;
		}
		else {
			memset (buf, 0xff, length);
			return COMMON_MATH_BOUNDARY_REACHED;
		}
	}
	else {
		buf[index]++;
	}

	return 0;
}
