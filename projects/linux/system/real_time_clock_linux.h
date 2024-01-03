// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef REAL_TIME_CLOCK_LINUX_H_
#define REAL_TIME_CLOCK_LINUX_H_

#include "system/real_time_clock.h"


/**
 * Real time clock that uses the Linux system time.
 */
struct real_time_clock_linux {
	struct real_time_clock base;		/**< The base real time clock interface. */
};


int real_time_clock_linux_init (struct real_time_clock_linux *rtc);
void real_time_clock_linux_release (const struct real_time_clock_linux *rtc);


#endif /* REAL_TIME_CLOCK_LINUX_H_ */