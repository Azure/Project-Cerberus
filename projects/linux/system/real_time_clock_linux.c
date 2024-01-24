// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "common/unused.h"
#include "system/real_time_clock_linux.h"


int real_time_clock_linux_get_time (const struct real_time_clock *rtc, uint64_t *msec)
{
	struct timespec now;
	int status;

	if ((rtc == NULL) || (msec == NULL)) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	status = clock_gettime (CLOCK_REALTIME, &now);
	if (status != 0) {
		return REAL_TIME_CLOCK_GET_TIME_FAILED;
	}

	/* Round to the nearest millisecond. */
	*msec = (now.tv_sec * 1000) + ((now.tv_nsec + 500000) / 1000000ULL);

	return 0;
}

int real_time_clock_linux_set_time (const struct real_time_clock *rtc, uint64_t msec)
{
	struct timespec now = { 0, };
	int status;

	if (rtc == NULL) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	now.tv_nsec = (msec % 1000) * 1000000;

	msec /= 1000;
	now.tv_sec = (time_t) msec;
	if ((uint64_t) now.tv_sec != msec) {
		return REAL_TIME_CLOCK_OUT_OF_RANGE;
	}

	errno = 0;
	status = clock_settime (CLOCK_REALTIME, &now);
	if (status == 0) {
		return 0;
	}

	if (errno == EPERM) {
		return REAL_TIME_CLOCK_UNSUPPORTED;
	}

	return REAL_TIME_CLOCK_SET_TIME_FAILED;
}

/**
 * Initialize a Linux real time clock instance.
 *
 * @param rtc The real time clock instance to initialize.
 *
 * @return 0 if the initialized was initialized successfully or an error code.
 */
int real_time_clock_linux_init (struct real_time_clock_linux *rtc)
{
	if (rtc == NULL) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	rtc->base.get_time = real_time_clock_linux_get_time;
	rtc->base.set_time = real_time_clock_linux_set_time;

	return 0;
}

/**
 * Release the resources used by a Linux real time clock instance.
 *
 * @param intf The real time clock instance to release.
 */
void real_time_clock_linux_release (const struct real_time_clock_linux *rtc)
{
	UNUSED (rtc);
}
