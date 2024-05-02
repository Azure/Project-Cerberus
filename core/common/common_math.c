// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "common_math.h"


/**
 * Count the number of bits that are set (1) in a single byte.
 *
 * @param byte The byte to check.
 * @param stop Bit position to stop looking for set bits.  If this is 8 or larger, the entire byte
 * will be checked.  If this is negative, only contiguous bits will be counted.
 *
 * @return Number of bits that are set in the specified byte.
 */
static int common_math_count_set_bits (uint8_t byte, int stop)
{
	int num_bits = 0;

	while ((byte != 0) && (stop != 0)) {
		if (byte & 0x01) {
			++num_bits;
		}
		else if (stop < 0) {
			stop = 1;
		}

		byte >>= 1;
		stop--;
	}

	return num_bits;
}

/**
 * Get the number of bits that are set (1) in a single byte.  Set bits do not need to be contiguous.
 *
 * @param byte Byte to check.
 *
 * @return Number of bits that are set in the specified byte.
 */
int common_math_get_num_bits_set (uint8_t byte)
{
	return common_math_count_set_bits (byte, 8);
}

/**
 * Get the number of bits that are set (1) in a single byte before a specific bit position.  Set
 * bits do not need to be contiguous.
 *
 * @param byte Byte to check.
 * @param index Bit position to stop looking for set bits.  If this is 8 or larger, the entire byte
 * will be checked.
 *
 * @return Number of bits that are set in the specified byte.
 */
int common_math_get_num_bits_set_before_index (uint8_t byte, uint8_t index)
{
	return common_math_count_set_bits (byte, index);
}

/**
 * Get the total number of bits that are set (1) in an array of bytes.  Set bits do not need to be
 * contiguous.
 *
 * @param bytes Byte array to check.
 * @param length Length of the array.
 *
 * @return Total number of bits that are set for all bytes in the array or an error code.
 */
int common_math_get_num_bits_set_in_array (const uint8_t *bytes, size_t length)
{
	size_t i;
	int bits = 0;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	for (i = 0; i < length; i++) {
		bits += common_math_count_set_bits (bytes[i], 8);
	}

	return bits;
}

/**
 * Get the number of contiguous bits that are set (1) in a single byte, starting from bit 0.  Any
 * bits after the first unset (0) bit will not be counted.
 *
 * @param byte Byte to check.
 *
 * @return Number of contiguous bits that are set in the specified byte.
 */
int common_math_get_num_contiguous_bits_set (uint8_t byte)
{
	return common_math_count_set_bits (byte, -1);
}

/**
 * Get the total number of contiguous bits that are set (1) in an array of bytes, starting from bit
 * 0 in byte 0.  Any bits after the first unset (0) bit will not be counted.
 *
 * @param bytes Byte array to check.
 * @param length Length of the array.
 *
 * @return Total number of contiguous bits that are set for all bytes in the array or an error code.
 */
int common_math_get_num_contiguous_bits_set_in_array (const uint8_t *bytes, size_t length)
{
	size_t i = 0;
	int bits = 8;
	int total = 0;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	while ((i < length) && (bits == 8)) {
		bits = common_math_count_set_bits (bytes[i++], -1);
		total += bits;
	}

	return total;
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
 * Check a byte array to see if it contains all zeros.
 *
 * @param bytes The byte array to check.
 * @param length Length of the byte array.
 *
 * @return true if all bytes are zero, false otherwise.  Empty or null arrays will return false.
 */
bool common_math_is_array_zero (const uint8_t *bytes, size_t length)
{
	if ((bytes == NULL) || (length == 0)) {
		return false;
	}

	/* memcmp is fine here since the comparison is against a constant value and timing attacks are
	 * not a concern. */
	return ((bytes[0] == 0) && (memcmp (bytes, &bytes[1], length - 1) == 0));
}

/**
 * Get the byte position and bit mask for a specific bit in an array of bytes.
 *
 * @param bytes The byte array.
 * @param length Length of the byte array.
 * @param bit The bit number in the array.
 * @param byte Output for the byte index in the array.
 * @param mask Output for the bit mask in the byte.
 *
 * @return 0 if the bit mask was successfully determined or an error code.
 */
static int common_math_get_bit_mask_in_array (const uint8_t *bytes, size_t length, size_t bit,
	size_t *byte, uint8_t *mask)
{
	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	*byte = bit / 8;
	*mask = 1U << (bit % 8);

	if (*byte >= length) {
		return COMMON_MATH_OUT_OF_RANGE;
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
int common_math_is_bit_set_in_array (const uint8_t *bytes, size_t length, size_t bit)
{
	size_t byte;
	uint8_t mask;
	int status;

	status = common_math_get_bit_mask_in_array (bytes, length, bit, &byte, &mask);
	if (status != 0) {
		return status;
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
	int status;

	status = common_math_get_bit_mask_in_array (bytes, length, bit, &byte, &mask);
	if (status != 0) {
		return status;
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
	int status;

	status = common_math_get_bit_mask_in_array (bytes, length, bit, &byte, &mask);
	if (status != 0) {
		return status;
	}

	bytes[byte] &= ~mask;

	return 0;
}

/**
 * Set the first bit in a byte array that is not already set.  The result will be a contiguous
 * series of set bits that is one bit longer than it was before the call.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 *
 * @return 0 if the bit was set or an error code.
 */
int common_math_set_next_bit_in_array (uint8_t *bytes, size_t length)
{
	int bits;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	/* Use the count of contiguous bits as the bit position for the next bit to set. */
	bits = common_math_get_num_contiguous_bits_set_in_array (bytes, length);

	return common_math_set_bit_in_array (bytes, length, bits);
}

/**
 * Set bits in a byte array until there are a specified count of contiguous bits.  If the count
 * check is already satisfied, no bits are set.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 * @param even 1 to grow to an even count, 0 for an odd count.
 *
 * @return 0 if the bits were set or an error code.
 */
static int common_math_set_contiguous_bits_to_count (uint8_t *bytes, size_t length, int even)
{
	int bits;

	if (bytes == NULL) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	bits = common_math_get_num_contiguous_bits_set_in_array (bytes, length);

	while ((bits % 2) == even) {
		bits = common_math_set_bit_in_array (bytes, length, bits);
		if (bits == COMMON_MATH_OUT_OF_RANGE) {
			return bits;
		}

		bits = common_math_get_num_contiguous_bits_set_in_array (bytes, length);
	}

	return 0;
}

/**
 * Set bits in a byte array until there is an even number of contiguous bits that are set.  If there
 * are already an even number of bits set, nothing will be done.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 *
 * @return 0 if the bits were set or an error code.
 */
int common_math_set_next_bit_in_array_even_count (uint8_t *bytes, size_t length)
{
	return common_math_set_contiguous_bits_to_count (bytes, length, 1);
}

/**
 * Set bits in a byte array until there is an odd number of contiguous bits that are set.  If there
 * are already an odd number of bits set, nothing will be done.
 *
 * @param bytes The byte array to update.
 * @param length Length of the byte array.
 *
 * @return 0 if the bits were set or an error code.
 */
int common_math_set_next_bit_in_array_odd_count (uint8_t *bytes, size_t length)
{
	return common_math_set_contiguous_bits_to_count (bytes, length, 0);
}
