// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_FREERTOS_H_
#define WORK_TASK_FREERTOS_H_

#include <stdint.h>
#include "FreeRTOS.h"
#include "task.h"
#include "system/work_task.h"


/**
 * Variable context for the FreeRTOS work task.
 */
struct work_task_freertos_state {
	struct work_task_state queue;	/**< Core queue state (entry list, lock, wake). */
	TaskHandle_t task;					/**< The FreeRTOS task that runs the worker loop. */
};

/**
 * FreeRTOS runner for a work task.  The portable core implements task queueing; this wrapper owns
 * the OS thread that services the task.
 */
struct work_task_freertos {
	struct work_task base;			/**< Portable work task queue. */
	struct work_task_freertos_state *state;	/**< Variable context for the task. */
};


int work_task_freertos_init (struct work_task_freertos *task,
	struct work_task_freertos_state *state);
int work_task_freertos_init_state (const struct work_task_freertos *task);
void work_task_freertos_release (const struct work_task_freertos *task);

#if configSUPPORT_DYNAMIC_ALLOCATION == 1
int work_task_freertos_allocate (const struct work_task_freertos *task, uint16_t stack_words,
	const char *task_name, int priority);
#endif

#if configSUPPORT_STATIC_ALLOCATION == 1
int work_task_freertos_allocate_static (const struct work_task_freertos *task,
	StaticTask_t *context, StackType_t *stack, uint32_t stack_words, const char *task_name,
	int priority);
#endif

void work_task_freertos_start (const struct work_task_freertos *task);


#endif	/* WORK_TASK_FREERTOS_H_ */
