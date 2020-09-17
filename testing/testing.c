// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "platform_io.h"


/**
 * Testing helper function to validate a byte array.
 *
 * @param expected The expected array.
 * @param actual The actual array.
 * @param length The length of the array.
 *
 * @return 0 if the actual array is correct or 1 if not.
 */
int testing_validate_array (const uint8_t *expected, const uint8_t *actual, size_t length)
{
	return testing_validate_array_prefix (expected, actual, length, "");
}

/**
 * Testing helper function to validate a byte array.
 *
 * @param expected The expected array.
 * @param actual The actual array.
 * @param length The length of the array.
 * @param prefix A prefix to prepend to error messages.
 *
 * @return 0 if the actual array is correct or 1 if not.
 */
int testing_validate_array_prefix (const uint8_t *expected, const uint8_t *actual, size_t length,
	const char *prefix)
{
	int failure = 0;
	unsigned int i;

	if (actual == NULL) {
		platform_printf ("Null array unexpected" NEWLINE);
		return 1;
	}

	for (i = 0; i < length; i++) {
		if (actual[i] != expected[i]) {
			platform_printf ("%sByte %u unexpected: expected=%x, actual=%x" NEWLINE, prefix, i,
				expected[i], actual[i]);
			failure = 1;
		}
	}

	return failure;
}
