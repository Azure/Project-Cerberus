// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef BUFFER_UTIL_H_
#define BUFFER_UTIL_H_

#include <stdint.h>
#include <stddef.h>


size_t buffer_copy (const uint8_t *src, size_t src_length, size_t *offset, size_t *dest_length,
	uint8_t *dest);


#endif /* BUFFER_UTIL_H_ */
