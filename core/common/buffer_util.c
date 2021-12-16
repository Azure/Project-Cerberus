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
