// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include "platform_api.h"
#include "platform_clock_freertos.h"


uint64_t platform_get_time (void)
{
	/* If there is no RTC available in the system, just get the elapsed time in milliseconds since
	 * last boot using the OS tick.  This doesn't manage wrap-around of the system tick, so that
	 * would look the same as a reboot event.
	 *
	 * If there is an RTC, it can be called by defining PLATFORM_RTC_GET_TIME to a function that
	 * will return the current RTC value, in milliseconds. */

#ifndef PLATFORM_RTC_GET_TIME
	return (uint64_t) xTaskGetTickCount () * portTICK_PERIOD_MS;
#else
	return PLATFORM_RTC_GET_TIME ();
#endif
}

int platform_init_timeout (uint32_t msec, platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	timeout->start = now;
	timeout->end = now;

	return platform_increase_timeout (msec, timeout);
}

int platform_increase_timeout (uint32_t msec, platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	timeout->end += msec / portTICK_PERIOD_MS;

	/* If the tick count has wrapped around since the timeout has started, reset the timeout start
	 * time to the current time.  The relative time to the end of the timer will remain, but the
	 * wrap condition will be removed. */
	if ((timeout->end < timeout->start) && (now < timeout->end)) {
		timeout->start = now;
	}

	return 0;
}

int platform_has_timeout_expired (const platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	if (timeout->end >= timeout->start) {
		/* No timer wrap around expected.  Check if the current tick count is between the start and
		 * end times. */
		if ((now >= timeout->start) && (now < timeout->end)) {
			return 0;
		}
		else {
			return 1;
		}
	}
	else {
		/* There is a timer wrap around expected.  Check if the current tick count is after the
		 * start time or before the end time, which are not contiguous values. */
		if ((now >= timeout->start) || (now < timeout->end)) {
			return 0;
		}
		else {
			return 1;
		}
	}
}

int platform_get_timeout_remaining (const platform_clock *timeout, uint32_t *msec)
{
	TickType_t now = xTaskGetTickCount ();
	uint32_t remaining = 0;

	if ((timeout == NULL) || (msec == NULL)) {
		return PLATFORM_TIMEOUT_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	if ((timeout->start <= timeout->end)) {
		/* No wrap in ticks is expected.  If the current tick falls within the timer bounds, find
		 * the amount of time until the end. */
		if ((now >= timeout->start) && (now < timeout->end)) {
			remaining = timeout->end - now;
		}
	}
	else {
		/* There is a wrap in ticks expected.  The current tick still needs to fall within the timer
		 * bounds, but the check and calculation is different due to the tick wrapping. */
		if (now >= timeout->start) {
			remaining = ((portMAX_DELAY - now) + 1) + timeout->end;
		}
		else if (now < timeout->end) {
			remaining = timeout->end - now;
		}
	}

	*msec = remaining * portTICK_PERIOD_MS;
	return 0;
}

int platform_init_current_tick (platform_clock *currtime)
{
	TickType_t now = xTaskGetTickCount ();

	if (currtime == NULL) {
		return PLATFORM_TIMEOUT_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	currtime->start = now;
	currtime->end = now;

	return 0;
}

uint32_t platform_get_duration (const platform_clock *start, const platform_clock *end)
{
	if ((end == NULL) || (start == NULL)) {
		return 0;
	}

	if (start->end <= end->end) {
		return (end->end - start->end) * portTICK_PERIOD_MS;
	}
	else {
		/* The ticks have wrapped.  The total duration is the time until the ticks wrapped plus the
		 * time that has passed since the ticks wrapped. */
		return (((portMAX_DELAY - start->end) + 1) + end->end) * portTICK_PERIOD_MS;
	}
}
