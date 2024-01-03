// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_LINUX_STATIC_H_
#define REAL_TIME_CLOCK_LINUX_STATIC_H_

#include "real_time_clock_linux.h"
#include "system/real_time_clock_static.h"


/* Internal functions declared to allow for static initialization. */

int real_time_clock_linux_get_time (const struct real_time_clock *rtc, uint64_t *msec);
int real_time_clock_linux_set_time (const struct real_time_clock *rtc, uint64_t msec);


/* Static initializer API. */

/**
 * Initializes the API for a static instance of a Linux real time clock.
 *
 * There is no validation done on the arguments.
 */
#define real_time_clock_linux_static_init() { \
		.base = real_time_clock_static_init (real_time_clock_linux_get_time, \
			real_time_clock_linux_set_time), \
	}


#endif /* REAL_TIME_CLOCK_LINUX_STATIC_H_ */
