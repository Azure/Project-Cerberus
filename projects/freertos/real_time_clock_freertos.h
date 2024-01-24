// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_FREERTOS_H_
#define REAL_TIME_CLOCK_FREERTOS_H_

#include "system/real_time_clock.h"


/**
 * Real time clock that uses the FreeRTOS system tick.
 */
struct real_time_clock_freertos {
	struct real_time_clock base;		/**< The base real time clock interface. */
};


int real_time_clock_freertos_init (struct real_time_clock_freertos *rtc);
void real_time_clock_freertos_release (const struct real_time_clock_freertos *rtc);


#endif /* REAL_TIME_CLOCK_FREERTOS_H_ */
