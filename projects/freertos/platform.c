// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "status/rot_status.h"


/* Error codes to use for platform API failures. */
#define	INVALID_ARGUMENT	0
#define	NO_MEMORY			1
#define	FAILURE				2


void* platform_calloc (size_t nmemb, size_t size)
{
	void *mem;

	mem = pvPortMalloc (nmemb * size);
	if (mem != NULL) {
		memset (mem, 0, nmemb * size);
	}

	return mem;
}

#if configFRTOS_MEMORY_SCHEME == 3
void* platform_realloc (void *ptr, size_t size)
{
	void *mem;

	vTaskSuspendAll ();
	{
		mem = realloc (ptr, size);
	}
	(void) xTaskResumeAll ();

	return mem;
}
#endif

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
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
	}

	timeout->start = now;
	timeout->end = now;

	return platform_increase_timeout (msec, timeout);
}

int platform_increase_timeout (uint32_t msec, platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
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
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
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
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
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
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
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

int platform_mutex_init (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	*mutex = xSemaphoreCreateMutex ();
	if (*mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (NO_MEMORY);
	}

	return 0;
}

int platform_mutex_free (platform_mutex *mutex)
{
	if (mutex && *mutex) {
		vSemaphoreDelete (*mutex);
	}

	return 0;
}

int platform_mutex_lock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTake (*mutex, portMAX_DELAY);
	return 0;
}

int platform_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreGive (*mutex);
	return 0;
}

int platform_recursive_mutex_init (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	*mutex = xSemaphoreCreateRecursiveMutex ();
	if (*mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (NO_MEMORY);
	}

	return 0;
}

int platform_recursive_mutex_lock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTakeRecursive (*mutex, portMAX_DELAY);
	return 0;
}

int platform_recursive_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreGiveRecursive (*mutex);
	return 0;
}

/**
 * Internal notification function for timer expiration.
 *
 * @param timer The timer that expired.
 */
static void platform_timer_notification (TimerHandle_t timer)
{
	platform_timer *instance = pvTimerGetTimerID (timer);

	if (instance) {
		xSemaphoreTakeRecursive (instance->disarm_lock, portMAX_DELAY);

		if (!instance->disarm) {
			instance->callback (instance->context);
		}

		xSemaphoreGiveRecursive (instance->disarm_lock);
	}
}

int platform_timer_create (platform_timer *timer, timer_callback callback, void *context)
{
	if ((timer == NULL) || (callback == NULL)) {
		return PLATFORM_TIMER_ERROR (INVALID_ARGUMENT);
	}

	timer->disarm_lock = xSemaphoreCreateRecursiveMutex ();
	if (timer->disarm_lock == NULL) {
		return PLATFORM_TIMER_ERROR (NO_MEMORY);
	}

	timer->timer = xTimerCreate ("SWTimer", 1, pdFALSE, timer, platform_timer_notification);
	if (timer->timer == NULL) {
		vSemaphoreDelete (timer->disarm_lock);
		return PLATFORM_TIMER_ERROR (NO_MEMORY);
	}

	timer->callback = callback;
	timer->context = context;
	timer->disarm = 1;

	return 0;
}

int platform_timer_arm_one_shot (platform_timer *timer, uint32_t ms_timeout)
{
	if ((timer == NULL) || (ms_timeout == 0)) {
		return PLATFORM_TIMER_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTakeRecursive (timer->disarm_lock, portMAX_DELAY);

	timer->disarm = 0;
	xTimerChangePeriod (timer->timer, pdMS_TO_TICKS (ms_timeout), portMAX_DELAY);
	xTimerReset (timer->timer, portMAX_DELAY);

	xSemaphoreGiveRecursive (timer->disarm_lock);

	return 0;
}

int platform_timer_disarm (platform_timer *timer)
{
	if (timer == NULL) {
		return PLATFORM_TIMER_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTakeRecursive (timer->disarm_lock, portMAX_DELAY);

	timer->disarm = 1;
	xTimerStop (timer->timer, portMAX_DELAY);

	xSemaphoreGiveRecursive (timer->disarm_lock);

	return 0;
}

void platform_timer_delete (platform_timer *timer)
{
	if (timer != NULL) {
		platform_timer_disarm (timer);

		platform_msleep (100);
		xTimerDelete (timer->timer, portMAX_DELAY);
		vSemaphoreDelete (timer->disarm_lock);
	}
}

int platform_semaphore_init (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (INVALID_ARGUMENT);
	}

	*sem = xSemaphoreCreateBinary ();
	if (*sem == NULL) {
		return PLATFORM_MUTEX_ERROR (NO_MEMORY);
	}

	return 0;
}

void platform_semaphore_free (platform_semaphore *sem)
{
	if (sem && *sem) {
		vSemaphoreDelete (*sem);
	}
}

int platform_semaphore_post (platform_semaphore *sem)
{
	BaseType_t status;

	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (INVALID_ARGUMENT);
	}

	status = xSemaphoreGive (*sem);
	return (status == pdTRUE) ? 0 : PLATFORM_SEMAPHORE_ERROR (FAILURE);
}

int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout)
{
	TickType_t timeout;
	BaseType_t status;

	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (INVALID_ARGUMENT);
	}

	if (ms_timeout == 0) {
		timeout = portMAX_DELAY;
	}
	else {
		timeout = pdMS_TO_TICKS (ms_timeout);
	}

	status = xSemaphoreTake (*sem, timeout);
	return (status == pdTRUE) ? 0 : 1;
}

int platform_semaphore_try_wait (platform_semaphore *sem)
{
	BaseType_t status;

	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (INVALID_ARGUMENT);
	}

	status = xSemaphoreTake (*sem, 0);
	return (status == pdTRUE) ? 0 : 1;
}

int platform_semaphore_reset (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTake (*sem, 0);
	return 0;
}
