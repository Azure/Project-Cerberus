// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CLOCK_UTILS_H_
#define CLOCK_UTILS_H_

#include <stdint.h>


/**
 * Determine the number of ticks at a particular clock frequency per millisecond.
 */
#define CLOCK_TICKS_PER_MS(clk)		((clk) / 1000)

/**
 * Round the clock ticks to the nearest millisecond.
 */
#define	CLOCK_ROUND_TICKS(x, clk)	((uint64_t) (x) + (CLOCK_TICKS_PER_MS (clk) / 2))

/**
 * Convert a clock counter value to milliseconds.  Round the result to the nearest millisecond.
 */
#define	CLOCK_TICKS_TO_MS(x, clk)	((CLOCK_ROUND_TICKS (x, clk) * 1000) / (clk))


#endif	// CLOCK_UTILS_H_
