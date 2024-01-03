// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_FREERTOS_STATIC_H_
#define REAL_TIME_CLOCK_FREERTOS_STATIC_H_

#include "real_time_clock_freertos.h"
#include "system/real_time_clock_static.h"


/* Internal functions declared to allow for static initialization. */

int real_time_clock_freertos_get_time (const struct real_time_clock *rtc, uint64_t *msec);


/* Static initializer API. */

/**
 * Initializes the API for a static instance of a FreeRTOS real time clock.
 *
 * There is no validation done on the arguments.
 */
#define real_time_clock_freertos_static_init() { \
		.base = real_time_clock_static_init (real_time_clock_freertos_get_time, NULL), \
	}


#endif /* REAL_TIME_CLOCK_FREERTOS_STATIC_H_ */
