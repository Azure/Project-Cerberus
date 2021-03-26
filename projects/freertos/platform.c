// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "task.h"
#include "status/rot_status.h"


#define	INVALID_ARGUMENT	0
#define	NO_MEMORY			1


/**
 * FreeRTOS implementation the standard library function 'calloc'.
 *
 * @param nmemb The number of elements to allocate.
 * @param size The size of each element.
 *
 * @return The allocated memory, initialized to 0.
 */
void* platform_calloc (size_t nmemb, size_t size)
{
	void *mem;

	mem = pvPortMalloc (nmemb * size);
	if (mem != NULL) {
		memset (mem, 0, nmemb * size);
	}

	return mem;
}

/**
 * FreeRTOS implementation for the standard library function 'realloc'.
 *
 * @param ptr The pointer to resize.
 * @param size The new size of the allocated memory.
 *
 * @return The resized memory.
 */
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


#define	PLATFORM_TIMEOUT_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_TIMEOUT, code)

/**
 * Initialize a clock structure to represent the time at which a timeout expires.
 *
 * @param msec The number of milliseconds to use for the timeout.
 * @param timeout The timeout clock to initialize.
 *
 * @return 0 if the timeout was initialized successfully or an error code.
 */
int platform_init_timeout (uint32_t msec, platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
	}

	timeout->ticks = now;
	timeout->wrap = 0;

	return platform_increase_timeout (msec, timeout);
}

/**
 * Increase the amount of time for an existing timeout.
 *
 * @param msec The number of milliseconds to increase the timeout expiration by.
 * @param timeout The timeout clock to update.
 *
 * @return 0 if the timeout was updated successfully or an error code.
 */
int platform_increase_timeout (uint32_t msec, platform_clock *timeout)
{
	TickType_t curr;

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
	}

	curr = timeout->ticks;

	timeout->ticks += msec / portTICK_PERIOD_MS;
	if ((timeout->wrap == 0) && (timeout->ticks < curr)) {
		timeout->wrap = 1;
	}

	return 0;
}

/**
 * Initialize a clock structure to represent current tick count.
 *
 * @param currtime The platform_clock type to initialize.
 *
 * @return 0 if the current tick count was initialized successfully or an error code.
 */
int platform_init_current_tick (platform_clock *currtime)
{
	TickType_t now = xTaskGetTickCount ();

	if (currtime == NULL) {
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
	}

	currtime->wrap = 0;
	currtime->ticks = now;

	return 0;
}

/**
 * Determine if the specified timeout has expired.
 *
 * @param timeout The timeout to check.
 *
 * @return 1 if the timeout has expired, 0 if it has not, or an error code.
 */
int platform_has_timeout_expired (platform_clock *timeout)
{
	TickType_t now = xTaskGetTickCount ();

	if (timeout == NULL) {
		return PLATFORM_TIMEOUT_ERROR (INVALID_ARGUMENT);
	}

	if (!timeout->wrap) {
		if (now < timeout->ticks) {
			return 0;
		}
		else {
			return 1;
		}
	}
	else {
		if ((now < 0xf0000000) && (now >= timeout->ticks)) {
			return 1;
		}
		else {
			return 0;
		}
	}
}

/**
 * Get the elapsed time in milliseconds since last boot
 *
 * @return elapsed time in milliseconds since last boot.
 */
uint64_t platform_get_time_since_boot (void)
{
	return (uint64_t) xTaskGetTickCount () * portTICK_PERIOD_MS;
}

/**
 * Get the duration between two clock instances.  These are expected to be initialized with
 * {@link platform_init_current_tick}.
 *
 * This is intended to measure small durations.  Very long durations may not be accurately
 * calculated due value limitations/overflow.
 *
 * @param start The start time for the time duration.
 * @param end The end time for the time duration.
 *
 * @return The elapsed time, in milliseconds.  If either clock is null, the elapsed time will be 0.
 */
uint32_t platform_get_duration (const platform_clock *start, const platform_clock *end)
{
	if ((end == NULL) || (start == NULL)) {
		return 0;
	}

	if (start->ticks <= end->ticks) {
		return (end->ticks - start->ticks) * portTICK_PERIOD_MS;
	}
	else {
		/* The ticks have wrapped. */
		return ((portMAX_DELAY - start->ticks) + end->ticks) * portTICK_PERIOD_MS;
	}
}


#define	PLATFORM_MUTEX_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_MUTEX, code)

/**
 * Initialize a FreeRTOS mutex.
 *
 * @param mutex The mutex to initialize.
 *
 * @return 0 if the mutex was successfully initialized or an error code.
 */
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

/**
 * Free a FreeRTOS mutex.
 *
 * @param mutex The mutex to free.
 *
 * @return 0 if the mutex was freed or an error code.
 */
int platform_mutex_free (platform_mutex *mutex)
{
	if (mutex && *mutex) {
		vSemaphoreDelete (*mutex);
	}

	return 0;
}

/**
 * Acquire the mutex lock.
 *
 * @param mutex The mutex to lock.
 *
 * @return 0 if the mutex was successfully locked or an error code.
 */
int platform_mutex_lock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTake (*mutex, portMAX_DELAY);
	return 0;
}

/**
 * Release the mutex lock.
 *
 * @param mutex The mutex to unlock.
 *
 * @return 0 if the mutex was successfully unlocked or an error code.
 */
int platform_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreGive (*mutex);
	return 0;
}

/**
 * Initialize a FreeRTOS recursive mutex.
 *
 * @param mutex The mutex to initialize.
 *
 * @return 0 if the mutex was successfully initialized or an error code.
 */
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

/**
 * Free a FreeRTOS recursive mutex.
 *
 * @param mutex The mutex to free.
 *
 * @return 0 if the mutex was freed or an error code.
 */
int platform_recursive_mutex_free (platform_mutex *mutex)
{
	if (mutex && *mutex) {
		vSemaphoreDelete (*mutex);
	}

	return 0;
}

/**
 * Acquire the recursive mutex lock.
 *
 * @param mutex The mutex to lock.
 *
 * @return 0 if the mutex was successfully locked or an error code.
 */
int platform_recursive_mutex_lock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreTakeRecursive (*mutex, portMAX_DELAY);
	return 0;
}

/**
 * Release the recursive mutex lock.
 *
 * @param mutex The mutex to unlock.
 *
 * @return 0 if the mutex was successfully unlocked or an error code.
 */
int platform_recursive_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (INVALID_ARGUMENT);
	}

	xSemaphoreGiveRecursive (*mutex);
	return 0;
}


#define	PLATFORM_TIMER_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, code)

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

/**
 * Create a timer that is not armed.
 *
 * @param timer The container for the created timer.
 * @param callback The function to call when the timer expires.
 * @param context The context to pass to the notification function.
 *
 * @return 0 if the timer was created or an error code.
 */
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

/**
 * Start a one-shot timer.  Calling this on an already armed timer will restart the timer with the
 * specified timeout.
 *
 * @param timer The timer to start.
 * @param ms_timeout The timeout to wait for timer expiration, in milliseconds.
 *
 * @return 0 if the timer has started or an error code.
 */
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

/**
 * Stop a timer.
 *
 * @param timer The timer to stop.
 *
 * @return 0 if the timer is stopped or an error code.
 */
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

/**
 * Delete and disarm a timer.  Do not delete a timer from within the context of the event callback.
 *
 * @param timer The timer to delete.
 */
void platform_timer_delete (platform_timer *timer)
{
	if (timer != NULL) {
		platform_timer_disarm (timer);

		platform_msleep (100);
		xTimerDelete (timer->timer, portMAX_DELAY);
		vSemaphoreDelete (timer->disarm_lock);
	}
}


#define	SWAP_BYTES_UINT32(x)	(((x >> 24) & 0xff) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | ((x << 24) & 0xff000000))
#define	SWAP_BYTES_UINT16(x)	(((x >> 8) & 0xff) | ((x << 8) & 0xff00))

/**
 * Convert the unsigned 32-bit integer host_long from host byte order to network byte order.
 * Assumes host byte order is different from network byte order.
 *
 * @param host_long The unsigned 32-bit integer to convert.
 */
uint32_t platform_htonl (uint32_t host_long)
{
	return SWAP_BYTES_UINT32 (host_long);
}

/**
 * Convert the unsigned 16-bit integer host_short from host byte order to network byte order.
 * Assumes host byte order is different from network byte order.
 *
 * @param host_short The unsigned 16-bit integer to convert.
 */
uint16_t platform_htons (uint16_t host_short)
{
	return SWAP_BYTES_UINT16 (host_short);
}
