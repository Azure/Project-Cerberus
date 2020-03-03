// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TESTING_H_
#define TESTING_H_

#include <stdint.h>
#include <stdio.h>
#include "CuTest/CuTest.h"
#include "platform_io.h"


/**
 * Macro to call at the beginning of every test for easier tracking at run-time.
 */
#define	TEST_START	platform_printf ("%s: %s"NEWLINE, SUITE, __func__)


int testing_validate_array (const uint8_t *expected, const uint8_t *actual, size_t length);
int testing_validate_array_prefix (const uint8_t *expected, const uint8_t *actual, size_t length,
	const char *prefix);


#endif /* TESTING_H_ */
