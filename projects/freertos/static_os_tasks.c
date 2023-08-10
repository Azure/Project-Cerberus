// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "FreeRTOS.h"
#include "task.h"


/* If static allocation is enabled for FreeRTOS, callback functions must be provided to provide
 * the memory used for internal OS tasks.  This is a generic implementation based on the example
 * from FreeRTOS documentation.  Platforms can choose to provide a different implementation if
 * desired. */

#if configSUPPORT_STATIC_ALLOCATION == 1

/* Define the memory for the Idle task. */
static StaticTask_t idle_task_tcb;
static StackType_t idle_task_stack[configMINIMAL_STACK_SIZE];

void vApplicationGetIdleTaskMemory (StaticTask_t **ppxIdleTaskTCBBuffer,
	StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize)
{
	*ppxIdleTaskTCBBuffer = &idle_task_tcb;
	*ppxIdleTaskStackBuffer = idle_task_stack;
	*pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}


#if configUSE_TIMERS == 1

/* Define the memory for the Timer task. */
static StaticTask_t timer_task_tcb;
static StackType_t timer_task_stack[configTIMER_TASK_STACK_DEPTH];

void vApplicationGetTimerTaskMemory (StaticTask_t **ppxTimerTaskTCBBuffer,
	StackType_t **ppxTimerTaskStackBuffer, uint32_t *pulTimerTaskStackSize)
{
	*ppxTimerTaskTCBBuffer = &timer_task_tcb;
	*ppxTimerTaskStackBuffer = timer_task_stack;
	*pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}

#endif
#endif
