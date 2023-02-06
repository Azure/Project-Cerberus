// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"


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

int platform_mutex_init (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*mutex = xSemaphoreCreateMutex ();
	if (*mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_NO_MEMORY);
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
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	xSemaphoreTake (*mutex, portMAX_DELAY);
	return 0;
}

int platform_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	xSemaphoreGive (*mutex);
	return 0;
}

int platform_recursive_mutex_init (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*mutex = xSemaphoreCreateRecursiveMutex ();
	if (*mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_NO_MEMORY);
	}

	return 0;
}

int platform_recursive_mutex_lock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	xSemaphoreTakeRecursive (*mutex, portMAX_DELAY);
	return 0;
}

int platform_recursive_mutex_unlock (platform_mutex *mutex)
{
	if (mutex == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_INVALID_ARGUMENT);
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
		return PLATFORM_TIMER_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	timer->disarm_lock = xSemaphoreCreateRecursiveMutex ();
	if (timer->disarm_lock == NULL) {
		return PLATFORM_TIMER_ERROR (PLATFORM_NO_MEMORY);
	}

	timer->timer = xTimerCreate ("SWTimer", 1, pdFALSE, timer, platform_timer_notification);
	if (timer->timer == NULL) {
		vSemaphoreDelete (timer->disarm_lock);
		return PLATFORM_TIMER_ERROR (PLATFORM_NO_MEMORY);
	}

	timer->callback = callback;
	timer->context = context;
	timer->disarm = 1;

	return 0;
}

int platform_timer_arm_one_shot (platform_timer *timer, uint32_t ms_timeout)
{
	if ((timer == NULL) || (ms_timeout == 0)) {
		return PLATFORM_TIMER_ERROR (PLATFORM_INVALID_ARGUMENT);
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
		return PLATFORM_TIMER_ERROR (PLATFORM_INVALID_ARGUMENT);
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
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem = xSemaphoreCreateBinary ();
	if (*sem == NULL) {
		return PLATFORM_MUTEX_ERROR (PLATFORM_NO_MEMORY);
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
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	status = xSemaphoreGive (*sem);
	return (status == pdTRUE) ? 0 : PLATFORM_SEMAPHORE_ERROR (PLATFORM_FAILURE);
}

int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout)
{
	TickType_t timeout;
	BaseType_t status;

	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
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
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	status = xSemaphoreTake (*sem, 0);
	return (status == pdTRUE) ? 0 : 1;
}

int platform_semaphore_reset (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	xSemaphoreTake (*sem, 0);
	return 0;
}
