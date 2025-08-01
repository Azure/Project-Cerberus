// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "buffer_util.h"
#include "common_math.h"


/**
 * Reverse the byte order for a 16-bit integer.
 *
 * @param data The input data.
 *
 * @return The 16-bit value in reversed byte order.
 */
uint16_t common_math_swap_bytes_uint16 (uint16_t data)
{
	return (((data >> 8) & 0xff) | ((data & 0xff) << 8));
}

/**
 * Reverse the byte order for a 32-bit integer.
 *
 * @param data The input data.
 *
 * @return The 32-bit value in reversed byte order.
 */
uint32_t common_math_swap_bytes_uint32 (uint32_t data)
{
	return common_math_swap_bytes_uint16 ((data >> 16) & 0xffff) |
		(common_math_swap_bytes_uint16 (data & 0xffff) << 16);
}

/**
 * Reverse the byte order for a 64-bit integer.
 *
 * @param data The input data.
 *
 * @return The 64-bit value in reversed byte order.
 */
uint64_t common_math_swap_bytes_uint64 (uint64_t data)
{
	return common_math_swap_bytes_uint32 ((data >> 32) & 0xffffffff) |
		((uint64_t) common_math_swap_bytes_uint32 (data & 0xffffffff) << 32);
}

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
 * Treat an arbitrary length byte array as a big endian integer and increment the value by 1.
 *
 * @param bytes Input array to be incremented as if it was a big endian integer.
 * @param len Length of the array.
 * @param allow_rollover Allows the array value to roll over to 0 when the upper boundary is
 * reached.
 *
 * @return 0 if the input array is incremented successfully or an error code.
 */
int common_math_increment_byte_array (uint8_t *bytes, size_t length, bool allow_rollover)
{
	size_t index;

	if ((bytes == NULL) || (length == 0)) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	index = length - 1;
	while ((index > 0) && (bytes[index] == 0xff)) {
		bytes[index--] = 0;
	}

	if ((index == 0) && (bytes[0] == 0xff)) {
		if (allow_rollover) {
			bytes[0] = 0;
		}
		else {
			memset (bytes, 0xff, length);

			return COMMON_MATH_BOUNDARY_REACHED;
		}
	}
	else {
		bytes[index]++;
	}

	return 0;
}

/**
 * Treat an arbitrary length byte array as a big endian integer and decrement the value by 1.
 *
 * @param bytes Input array to be decremented as if it was a big endian integer.
 * @param len Length of the array.
 * @param allow_rollover Allows the array value to roll over to the maximum value when 0 is reached.
 *
 * @return 0 if the input array is decremented successfully or an error code.
 */
int common_math_decrement_byte_array (uint8_t *bytes, size_t length, bool allow_rollover)
{
	size_t index;

	if ((bytes == NULL) || (length == 0)) {
		return COMMON_MATH_INVALID_ARGUMENT;
	}

	index = length - 1;
	while ((index > 0) && (bytes[index] == 0)) {
		bytes[index--] = 0xff;
	}

	if ((index == 0) && (bytes[0] == 0)) {
		if (allow_rollover) {
			bytes[0] = 0xff;
		}
		else {
			memset (bytes, 0, length);

			return COMMON_MATH_BOUNDARY_REACHED;
		}
	}
	else {
		bytes[index]--;
	}

	return 0;
}

/**
 * Treat arbitrary length byte arrays an big endian integers and compare their values.  This
 * provides the same functionality as memcmp, but operates in constant time when the input buffers
 * are the same length.
 *
 * @param bytes1 The byte array that is being checked.
 * @param length1 Length of the first byte array.
 * @param bytes2 A reference byte array to compare against.
 * @param length2 Length of the second byte array.
 *
 * @return 0 if both arrays are the same, a positive number if the checked array is larger than the
 * reference array, or a negative number if the checked array is less than the reference array.
 */
int common_math_compare_array (const uint8_t *bytes1, size_t length1, const uint8_t *bytes2,
	size_t length2)
{
	bool is_empty[2];
	size_t length_diff;
	size_t i;
	int result = 0;

	is_empty[0] = ((bytes1 == NULL) || (length1 == 0));
	is_empty[1] = ((bytes2 == NULL) || (length2 == 0));

	if (is_empty[0] && is_empty[1]) {
		/* Both are empty. */
		return 0;
	}
	else if (is_empty[0]) {
		/* Only the array being checked is empty.  The array is smaller then the reference. */
		return -1;
	}
	else if (is_empty[1]) {
		/* Only array being compared against is empty.  The array is larger than the reference. */
		return 1;
	}

	/* Both arrays are not empty.  Compare the lengths. */
	if (length1 > length2) {
		length_diff = length1 - length2;

		if (common_math_is_array_zero (bytes1, length_diff)) {
			/* All the extra bytes in the array to check are zero.  Run a comparison against the
			 * reference, skipping all the leading zeros. */
			bytes1 += length_diff;
			length1 -= length_diff;
		}
		else {
			/* The array being checked has more non-zero bytes, so is a larger value. */
			return 1;
		}
	}
	else if (length1 < length2) {
		length_diff = length2 - length1;

		if (common_math_is_array_zero (bytes2, length_diff)) {
			/* All the extra bytes in the reference array are zero.  Run a comparison with the array
			 * being checked, skipping all the leading zeros. */
			bytes2 += length_diff;
			length2 -= length_diff;
		}
		else {
			/* The array being checked has fewer non-zero bytes, so is a smaller value. */
			return -1;
		}
	}

	/* The arrays are the same length, so compare the contents, ensuring that every byte is checked
	 * and with the same amount of processing. */
	for (i = 0; i < length1; i++) {
		int diff = (int) bytes1[i] - (int) bytes2[i];
		int mask = (result == 0) ? -1 : 0;

		result = (result & ~mask) | (diff & mask);
	}

	return result;
}

/**
 * Check a byte array to see if it contains all zeros.  This operation will be performed in constant
 * time.
 *
 * @param bytes The byte array to check.
 * @param length Length of the byte array.
 *
 * @return true if all bytes are zero, false otherwise.  Empty or null arrays will return false.
 */
bool common_math_is_array_zero (const uint8_t *bytes, size_t length)
{
	bool is_zero = true;
	size_t i;

	if ((bytes == NULL) || (length == 0)) {
		return false;
	}

	for (i = 0; i < length; i++) {
		is_zero &= (bytes[i] == 0);
	}

	return is_zero;
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

/**
 * Shift all the bits in an array to the right, starting from the beginning of the array.  Left-most
 * bits will be filled with zeros.
 *
 * @param bytes The byte array to shift.
 * @param length Length of the byte array.
 * @param shift_bits The number of bits to shift the array.
 */
void common_math_right_shift_array (uint8_t *bytes, size_t length, size_t shift_bits)
{
	size_t i;
	size_t shift_bytes;

	if ((bytes == NULL) || (length == 0) || (shift_bits == 0)) {
		/* Nothing to do. */
		return;
	}

	shift_bytes = shift_bits / 8;
	shift_bits %= 8;

	if (shift_bytes >= length) {
		/* The requested shift is larger then the array, so just clear the entire array. */
		memset (bytes, 0, length);

		return;
	}

	/* Handle full bytes by moving the whole array to the right. */
	memmove (&bytes[shift_bytes], bytes, length - shift_bytes);
	memset (bytes, 0, shift_bytes);

	/* Shift each byte, wrapping from the previous byte. */
	for (i = (length - 1); i > shift_bytes; i--) {
		bytes[i] = (bytes[i - 1] << (8 - shift_bits)) | (bytes[i] >> shift_bits);
	}

	/* Shift the first byte. */
	bytes[shift_bytes] >>= shift_bits;
}

/**
 * Shift all the bits in an array to the left, starting from the beginning of the array.  Right-most
 * bits will be filled with zeros.
 *
 * @param bytes The byte array to shift.
 * @param length Length of the byte array.
 * @param shift_bits The number of bits to shift the array.
 */
void common_math_left_shift_array (uint8_t *bytes, size_t length, size_t shift_bits)
{
	size_t i;
	size_t shift_bytes;

	if ((bytes == NULL) || (length == 0) || (shift_bits == 0)) {
		/* Nothing to do. */
		return;
	}

	shift_bytes = shift_bits / 8;
	shift_bits %= 8;

	if (shift_bytes >= length) {
		/* The requested shift is larger then the array, so just clear the entire array. */
		memset (bytes, 0, length);

		return;
	}

	/* Handle full bytes by moving the whole array to the left. */
	length -= shift_bytes;
	memmove (bytes, &bytes[shift_bytes], length);
	memset (&bytes[length], 0, shift_bytes);

	/* Shift each byte, wrapping from the next byte. */
	for (i = 0; i < (length - 1); i++) {
		bytes[i] = (bytes[i] << shift_bits) | (bytes[i + 1] >> (8 - shift_bits));
	}

	/* Shift the last byte. */
	bytes[length - 1] <<= shift_bits;
}

/**
 * Saturating increment for 8-bit unsigned integer.
 *
 * @param value The value to increment.
 *
 * @return The incremented value, or UINT8_MAX if the value is already at the maximum.
 */
uint8_t common_math_saturating_increment_u8 (uint8_t value)
{
	return ((value == UINT8_MAX) ? UINT8_MAX : (value + 1));
}

/**
 * Saturating increment for 16-bit unsigned integer.
 *
 * @param value The value to increment.
 *
 * @return The incremented value, or UINT16_MAX if the value is already at the maximum.
 */
uint16_t common_math_saturating_increment_u16 (uint16_t value)
{
	return ((value == UINT16_MAX) ? UINT16_MAX : (value + 1));
}

/**
 * Saturating increment for 32-bit unsigned integer.
 *
 * @param value The value to increment.
 *
 * @return The incremented value, or UINT32_MAX if the value is already at the maximum.
 */
uint32_t common_math_saturating_increment_u32 (uint32_t value)
{
	return ((value == UINT32_MAX) ? UINT32_MAX : (value + 1));
}
