// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "real_time_clock.h"
#include "common/unused.h"


int real_time_clock_set_time_unsupported (const struct real_time_clock *rtc, uint64_t msec)
{
	UNUSED (msec);

	if (rtc == NULL) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	return REAL_TIME_CLOCK_UNSUPPORTED;
}