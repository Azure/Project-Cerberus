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
 * Increments a byte array of arbitrary length by 1.
 *
 * @param buf Input array to be incremented.  This will be treated as a big endian value.
 * @param len Length of the array.
 * @param allow_rollover Allows the array value to roll over to 0 when upper boundary is reached.
 *
 * @return 0 if the input array is incremented successfully or an error code.
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

/**
 * Check a specific bit position in a byte array and determine if that bit is set.  Bit number is
 * determined as bits 0-7 in byte 0, bits 8-15 in byte 1, bits 16-23 in byte 2, etc.
 *
 * @param bytes The byte array to check.
 * @param length Length of the byte array.
 * @param bit The bit number in the array to check.
 *
 * @return 1 if the bit is set, 0 if the bit is clear, or an error code.
 */
int common_math_is_bit_set_in_array (uint8_t *bytes, size_t length, size_t bit)
{
	size_t byte;
	uint8_t mask;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	byte = bit / 8;
	mask = 1U << (bit % 8);

	if (byte >= length) {
		return COMMON_MATH_OUT_OF_RANGE;
	}

	return !!(bytes[byte] & mask);
}

/**
 * Set a bit at a specific bit position in a byte array.  Bit number is determined as bits 0-7 in
 * byte 0, bits 8-15 in byte 1, bits 16-23 in byte 2, etc.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 * @param bit The bit number in the array to set.
 *
 * @return 0 if the bit was set or an error code.
 */
int common_math_set_bit_in_array (uint8_t *bytes, size_t length, size_t bit)
{
	size_t byte;
	uint8_t mask;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	byte = bit / 8;
	mask = 1U << (bit % 8);

	if (byte >= length) {
		return COMMON_MATH_OUT_OF_RANGE;
	}

	bytes[byte] |= mask;

	return 0;
}

/**
 * Clear a bit at a specific bit position in a byte array.  Bit number is determined as bits 0-7 in
 * byte 0, bits 8-15 in byte 1, bits 16-23 in byte 2, etc.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 * @param bit The bit number in the array to clear.
 *
 * @return 0 if the bit was cleared or an error code.
 */
int common_math_clear_bit_in_array (uint8_t *bytes, size_t length, size_t bit)
{
	size_t byte;
	uint8_t mask;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	byte = bit / 8;
	mask = ~(1U << (bit % 8));

	if (byte >= length) {
		return COMMON_MATH_OUT_OF_RANGE;
	}

	bytes[byte] &= mask;

	return 0;
}
