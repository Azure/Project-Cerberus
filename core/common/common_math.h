// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef COMMON_MATH_H_
#define COMMON_MATH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * Determine the minimum of two numbers.
 */
#define	min(a, b)	(((a) < (b)) ? (a) : (b))

/**
 * @deprecated Reverse the byte order for a 16-bit integer.
 */
#define	SWAP_BYTES_UINT16(x)	common_math_swap_bytes_uint16 (x)

/**
 * @deprecated Reverse the byte order for a 32-bit integer.
 */
#define	SWAP_BYTES_UINT32(x)    common_math_swap_bytes_uint32 (x)

uint16_t common_math_swap_bytes_uint16 (uint16_t data);
uint32_t common_math_swap_bytes_uint32 (uint32_t data);
uint64_t common_math_swap_bytes_uint64 (uint64_t data);

int common_math_get_num_bits_set (uint8_t byte);
int common_math_get_num_bits_set_before_index (uint8_t byte, uint8_t index);
int common_math_get_num_bits_set_in_array (const uint8_t *bytes, size_t length);

int common_math_get_num_contiguous_bits_set (uint8_t byte);
int common_math_get_num_contiguous_bits_set_in_array (const uint8_t *bytes, size_t length);

int common_math_increment_byte_array (uint8_t *bytes, size_t length, bool allow_rollover);
int common_math_decrement_byte_array (uint8_t *bytes, size_t length, bool allow_rollover);

int common_math_compare_array (const uint8_t *bytes1, size_t length1, const uint8_t *bytes2,
	size_t length2);
bool common_math_is_array_zero (const uint8_t *bytes, size_t length);

int common_math_is_bit_set_in_array (const uint8_t *bytes, size_t length, size_t bit);
int common_math_set_bit_in_array (uint8_t *bytes, size_t length, size_t bit);
int common_math_clear_bit_in_array (uint8_t *bytes, size_t length, size_t bit);

int common_math_set_next_bit_in_array (uint8_t *bytes, size_t length);
int common_math_set_next_bit_in_array_even_count (uint8_t *bytes, size_t length);
int common_math_set_next_bit_in_array_odd_count (uint8_t *bytes, size_t length);

void common_math_right_shift_array (uint8_t *bytes, size_t length, size_t shift_bits);
void common_math_left_shift_array (uint8_t *bytes, size_t length, size_t shift_bits);

uint8_t common_math_saturating_increment_u8 (uint8_t value);
uint16_t common_math_saturating_increment_u16 (uint16_t value);
uint32_t common_math_saturating_increment_u32 (uint32_t value);


#define	COMMON_MATH_ERROR(code)				ROT_ERROR (ROT_MODULE_COMMON_MATH, code)

/**
 * Error codes that can be generated by the common math functions.
 */
enum {
	COMMON_MATH_INVALID_ARGUMENT = COMMON_MATH_ERROR (0x00),	/**< Input parameter is null or not valid. */
	COMMON_MATH_NO_MEMORY = COMMON_MATH_ERROR (0x01),			/**< Memory allocation failed. */
	COMMON_MATH_BOUNDARY_REACHED = COMMON_MATH_ERROR (0x02),	/**< Upper boundary of an array or a counter is reached. */
	COMMON_MATH_OUT_OF_RANGE = COMMON_MATH_ERROR (0x03),		/**< The request is out of the valid range. */
};


#endif	//COMMON_MATH_H_
