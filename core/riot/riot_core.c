// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "riot_core.h"


/**
 * Clear a memory region in a way that won't be optimized out by compliers.
 *
 * @param data The data buffer to clear.
 * @param length The number of bytes to clear.
 */
void riot_core_clear (void *data, size_t length)
{
	volatile uint8_t *clear = data;
	while (length--) {
		*clear++ = 0;
	}
}
