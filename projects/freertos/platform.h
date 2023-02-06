// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <stdint.h>
#include "platform_compiler.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "timers.h"
#include "common/common_math.h"
#ifndef PLATFORM_CLOCK_API
#include "platform_clock_freertos.h"
#else
/* Use a different, platform-specific implementation for platform_clock APIs instead of using the
 * generic implementation that leverages the FreeRTOS tick count.  This can be useful for platforms
 * that have an RTC and/or free-running counter with better granularity or bit width than the tick
 * count. */
#include PLATFORM_CLOCK_API
#endif


/* FreeRTOS memory management. */
#define	platform_malloc		pvPortMalloc
#define	platform_free		vPortFree


/* Use common byte swapping macros.  Assumes a little endian CPU. */
#define	platform_htonl	SWAP_BYTES_UINT32
#define	platform_htons	SWAP_BYTES_UINT16


/* Use the standard delay function to sleep. */
#define	platform_msleep(x)	vTaskDelay (pdMS_TO_TICKS (x) + 1)


/* FreeRTOS mutex. */
typedef SemaphoreHandle_t platform_mutex;

/* free is the same call for recursive mutexes. */
#define	platform_recursive_mutex_free(x)		platform_mutex_free (x)


/**
 * Container for managing a timer using FreeRTOS timers.
 */
typedef struct {
	TimerHandle_t timer;
	SemaphoreHandle_t disarm_lock;
	timer_callback callback;
	void *context;
	uint8_t disarm;
} platform_timer;


/* FreeRTOS semaphore */
typedef SemaphoreHandle_t platform_semaphore;


#endif /* PLATFORM_H_ */
