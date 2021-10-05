// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BUFFER_UTIL_H_
#define BUFFER_UTIL_H_

#include <stdint.h>
#include <stddef.h>


/**
 * Check if two buffers overlap.
 *
 * @param buf1 Pointer start address of first buffer.
 * @param buf1_len Length of first buffer.
 * @param buf2 Pointer start address of second buffer.
 * @param buf2_len Length of second buffer.
 */
#define buffer_util_check_if_buffers_overlap(buf1, buf1_len, buf2, buf2_len) \
	(((buf1 >= buf2) && (buf1 < (buf2 + buf2_len))) || ((buf2 >= buf1) && (buf2 < (buf1 + buf1_len))))


size_t buffer_copy (const uint8_t *src, size_t src_length, size_t *offset, size_t *dest_length,
	uint8_t *dest);


#endif /* BUFFER_UTIL_H_ */
