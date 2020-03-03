// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"


/**
 * GCC implementation for the strnlen function.
 *
 * @param s The string to determine the length of.
 * @param maxLen The maximum number of bytes in the string to count.
 *
 * @return The length of the string or maxLen if there is no NULL byte in the string.
 */
size_t strnlen (const char *s, size_t maxLen)
{
	size_t length = 0;
	
	if (s != NULL) {
		while ((*s != '\0') && (length < maxLen)) {
			length++;
			s++;
		}
	}

	return length;
}
