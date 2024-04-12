// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "buffer_util.h"
#include "common_math.h"


/**
 * Copy data into an output buffer.
 *
 * @param src The source data to copy.  If this is null, no data will be copied.
 * @param src_length Length of the source data buffer.
 * @param offset Offset in the source buffer to start copying.  On output, this will value will be
 * reduced by the number of bytes skipped in the source buffer.  If this is null, data will be
 * copied from the beginning of the source buffer.
 * @param dest_length Maximum number of bytes to copy.  On output, this will be reduced by the
 * number of bytes copied.  If this is null, no data will be copied.
 * @param dest Output buffer to copy data to.  If this is null, no data will be copied.
 *
 * @return The number of bytes copied.
 */
size_t buffer_copy (const uint8_t *src, size_t src_length, size_t *offset, size_t *dest_length,
	uint8_t *dest)
{
	size_t bytes;
	size_t start;

	if ((src == NULL) || (dest == NULL) || (src_length == 0)) {
		return 0;
	}

	if (offset) {
		start = *offset;

		if (start >= src_length) {
			*offset -= src_length;
			return 0;
		}
	}
	else {
		start = 0;
	}

	if (!dest_length) {
		return 0;
	}
	else {
		bytes = min (src_length - start, *dest_length);
	}

	memcpy (dest, &src[start], bytes);

	if (offset) {
		*offset = 0;
	}
	*dest_length -= bytes;

	return bytes;
}

/**
 * Reverse the contents of a buffer, i.e. make the last byte first and first byte last.
 *
 * @param buffer The buffer to reverse.  The reversed data will be stored in the same buffer.
 * @param length The number of bytes contained in the buffer.
 */
void buffer_reverse (uint8_t *buffer, size_t length)
{
	if (buffer != NULL) {
		size_t i;
		size_t j;
		uint8_t temp;

		for (i = 0, j = (length - 1); i < (length / 2); i++, j--) {
			temp = buffer[i];
			buffer[i] = buffer[j];
			buffer[j] = temp;
		}
	}
}

/**
 * Make a copy of a buffer, reversing the buffer contents.  If either buffer is null, no operation
 * is performed.
 *
 * These buffers must not be overlapping.
 *
 * The arguments on this function are reverse the normal semantics of input args first and output
 * args last, but this signature more closely maps to memcpy, making it more intuitive.
 *
 * @param dest Destination buffer for the reversed data.
 * @param src The buffer data to copy.
 * @param length The number of bytes to copy.
 */
void buffer_reverse_copy (uint8_t *dest, const uint8_t *src, size_t length)
{
	if ((src != NULL) && (dest != NULL)) {
		size_t i;
		size_t j;

		for (i = 0, j = (length - 1); i < length; i++, j--) {
			dest[i] = src[j];
		}
	}
}

/**
 * Make a copy of a buffer, reversing the buffer contents one DWORD at a time.  This function will
 * return error if either buffer is null or not DWORD aligned.
 * 
 * These buffers must not be overlapping.
 *
 * The arguments on this function are reverse the normal semantics of input args first and output
 * args last, but this signature more closely maps to memcpy, making it more intuitive.
 *
 * @param dest Destination buffer for the reversed data.
 * @param src The buffer data to copy.
 * @param length The number of dwords to copy.
 * 
 * @return 0 if the operation was successful or an error code.
 */
int buffer_reverse_copy_dwords (uint32_t *dest, const uint32_t *src, size_t length)
{
	size_t i;
	size_t j;

	if (((uintptr_t) src & 0x3U) || ((uintptr_t) dest & 0x3U)) {
		return BUFFER_UTIL_UNEXPETCED_ALIGNMENT;
	}
	
	if ((src == NULL) || (dest == NULL)) {
		return BUFFER_UTIL_INVALID_ARGUMENT;
	}

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		dest[i] = src[j];
	}

	return 0;
}

/**
 * A constant time replacement for memcmp for use in secure contexts.
 *
 * @param buf1 First input buffer for the comparison.
 * @param buf2 Second input buffer for the comparison.
 * @param length Length of buffers to compare.
 *
 * @return 0 if the buffers match exactly or BUFFER_UTIL_DATA_MISMATCH if they do not.
 */
int buffer_compare (const uint8_t *buf1, const uint8_t *buf2, size_t length)
{
	uint8_t match = 0xff;
	uint8_t check;
	size_t i;

	if ((buf1 == NULL) || (buf2 == NULL)) {
		if ((buf1 == NULL) && (buf2 == NULL) && (length == 0)) {
			return 0;
		}

		return BUFFER_UTIL_DATA_MISMATCH;
	}

	for (i = 0; i < length; i++) {
		check = buf1[i] ^ 0xff;
		check ^= buf2[i];
		match &= check;
	}

	return (match == 0xff) ? 0 : BUFFER_UTIL_DATA_MISMATCH;
}

/**
 * A constant time replacement for memcmp for use in secure contexts.  This version operates only on
 * buffers of 32-bit arrays, which is useful in scenarios where byte access is not possible.
 *
 * @param buf1 First input buffer for the comparison.
 * @param buf2 Second input buffer for the comparison.
 * @param length The number of 32-bit values to compare.
 *
 * @return 0 if the buffers match exactly or BUFFER_UTIL_DATA_MISMATCH if they do not.
 */
int buffer_compare_dwords (const uint32_t *buf1, const uint32_t *buf2, size_t dwords)
{
	uint32_t match = 0xffffffff;
	uint32_t check;
	size_t i;

	if ((buf1 == NULL) || (buf2 == NULL)) {
		if ((buf1 == NULL) && (buf2 == NULL) && (dwords == 0)) {
			return 0;
		}

		return BUFFER_UTIL_DATA_MISMATCH;
	}

	for (i = 0; i < dwords; i++) {
		check = buf1[i] ^ 0xffffffff;
		check ^= buf2[i];
		match &= check;
	}

	return (match == 0xffffffff) ? 0 : BUFFER_UTIL_DATA_MISMATCH;
}

/* Set up a pointer to abstract memset calls from the compiler.  This is not foolproof, but is the
 * default approach used by mbedTLS.  A better alternative is to use memset_s, but compiler support
 * for that seems to be poor.
 *
 * Reference:  http://www.daemonology.net/blog/2014-09-04-how-to-zero-a-buffer.html */
static void* (*const volatile memset_ptr) (void*, int, size_t) = memset;

/**
 * Clear a buffer by filling it with zeros.  This is not necessarily achieved in the most efficient
 * way, but is implemented in a way that should keep it from getting optimized out by compilers.
 *
 * @param buffer The buffer to clear.
 * @param length Length of the buffer.
 */
void buffer_zeroize (void *buffer, size_t length)
{
	if (buffer) {
		memset_ptr (buffer, 0, length);
	}
}

/**
 * Copies a 16 bit value between 2 assumed unaligned addresses.
 *
 * This does not do any validation on the parameters.
 *
 * @param dst A pointer to copy the value to.
 * @param src The address pointer to read from.
 */
void buffer_unaligned_copy16 (uint16_t *dst, const uint16_t *src)
{
#ifdef UNALIGNED_16BIT_MEMORY_ACCESS_NOT_SUPPORTED
	uint8_t *dst_copy = (uint8_t*) dst;

	memcpy (dst_copy, src, sizeof (*dst));
#else
	*dst = *src;
#endif
}

/**
 * Copies a 24 bit value between 2 assumed unaligned addresses.
 *
 * This does not do any validation on the parameters.
 *
 * @param dst A pointer to copy the value to.
 * @param src The address pointer to read from.
 */
void buffer_unaligned_copy24 (uint8_t *dst, const uint8_t *src)
{
	memcpy (dst, src, 3);
}

/**
 * Copies a 32 bit value between 2 assumed unaligned addresses.
 *
 * This does not do any validation on the parameters.
 *
 * @param dst The address pointer to read from.
 * @param src A pointer to copy the value to.
 */
void buffer_unaligned_copy32 (uint32_t *dst, const uint32_t *src)
{
#ifdef UNALIGNED_32BIT_MEMORY_ACCESS_NOT_SUPPORTED
	uint8_t *dst_copy = (uint8_t*) dst;

	memcpy (dst_copy, src, sizeof (*dst));
#else
	*dst = *src;
#endif
}

/**
 * Copies a 64 bit value between 2 assumed unaligned addresses.
 *
 * This does not do any validation on the parameters.
 *
 * @param dst The address pointer to read from.
 * @param src A pointer to copy the value to.
 */
void buffer_unaligned_copy64 (uint64_t *dst, const uint64_t *src)
{
#ifdef UNALIGNED_64BIT_MEMORY_ACCESS_NOT_SUPPORTED
	uint8_t *dst_copy = (uint8_t*) dst;

	memcpy (dst_copy, src, sizeof (*dst));
#else
	*dst = *src;
#endif
}

/**
 * Reads a 16 bit value from an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to read from.
 */
uint16_t buffer_unaligned_read16 (const uint16_t *buffer)
{
	uint16_t value;

	buffer_unaligned_copy16 (&value, buffer);

	return value;
}

/**
 * Reads a 24 bit value from an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to read from.
 */
uint32_t buffer_unaligned_read24 (const uint8_t *buffer)
{
	uint32_t value = 0;

	buffer_unaligned_copy24 ((uint8_t*)&value, buffer);

	return value;
}

/**
 * Reads a 32 bit value from an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to read from.
 */
uint32_t buffer_unaligned_read32 (const uint32_t *buffer)
{
	uint32_t value;

	buffer_unaligned_copy32 (&value, buffer);

	return value;
}

/**
 * Reads a 64 bit value from an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to read from.
 */
uint64_t buffer_unaligned_read64 (const uint64_t *buffer)
{
	uint64_t value;

	buffer_unaligned_copy64 (&value, buffer);

	return value;
}

/**
 * Writes a 16 bit value to an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to write to.
 * @param value The value to write.
 */
void buffer_unaligned_write16 (uint16_t *buffer, uint16_t value)
{
	buffer_unaligned_copy16 (buffer, &value);
}

/**
 * Writes a 24 bit value to an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to write to.
 * @param value The value to write.
 */
void buffer_unaligned_write24 (uint8_t *buffer, uint32_t value)
{
	buffer_unaligned_copy24 (buffer, (const uint8_t*)&value);
}

/**
 * Writes a 32 bit value to an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to write to.
 * @param value The value to write.
 */
void buffer_unaligned_write32 (uint32_t *buffer, uint32_t value)
{
	buffer_unaligned_copy32 (buffer, &value);
}

/**
 * Writes a 64 bit value to an assumed unaligned address.
 *
 * This does not do any validation on the parameters.
 *
 * @param buffer The address pointer to write to.
 * @param value The value to write.
 */
void buffer_unaligned_write64 (uint64_t *buffer, uint64_t value)
{
	buffer_unaligned_copy64 (buffer, &value);
}
