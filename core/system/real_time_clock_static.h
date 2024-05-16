// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_STATIC_H_
#define REAL_TIME_CLOCK_STATIC_H_

#include "real_time_clock.h"


/* Static initializer API for derived types. */

/**
 * Initializes the base API for a static instance of a real time clock.
 *
 * There is no validation done on the arguments.
 *
 * @param get_func A function pointer to handle the time getter.  This cannot be NULL.
 * @param set_func A function pointer to handle the time setter.  This cannot be NULL.
 */
#define real_time_clock_static_init(get_func, set_func) { \
		.get_time = get_func, \
		.set_time = set_func, \
	}


#endif	/* REAL_TIME_CLOCK_STATIC_H_ */
