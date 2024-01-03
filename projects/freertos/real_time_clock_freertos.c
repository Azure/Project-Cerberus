// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "FreeRTOS.h"
#include "task.h"
#include "common/unused.h"
#include "real_time_clock_freertos.h"


int real_time_clock_freertos_get_time (const struct real_time_clock *rtc, uint64_t *msec)
{
	if ((rtc == NULL) || (msec == NULL)) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	*msec = (uint64_t) xTaskGetTickCount () * portTICK_PERIOD_MS;

	return 0;
}

/**
 * Initialize a FreeRTOS real time clock instance.
 *
 * @param rtc The real time clock instance to initialize.
 *
 * @return 0 if the initialized was initialized successfully or an error code.
 */
int real_time_clock_freertos_init (struct real_time_clock_freertos *rtc)
{
	if (rtc == NULL) {
		return REAL_TIME_CLOCK_INVALID_ARGUMENT;
	}

	rtc->base.get_time = real_time_clock_freertos_get_time;
	rtc->base.set_time = real_time_clock_set_time_unsupported;

	return 0;
}

/**
 * Release the resources used by a FreeRTOS real time clock instance.
 *
 * @param intf The real time clock instance to release.
 */
void real_time_clock_freertos_release (const struct real_time_clock_freertos *rtc)
{
	UNUSED (rtc);
}