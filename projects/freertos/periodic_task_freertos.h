// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_TASK_FREERTOS_H_
#define PERIODIC_TASK_FREERTOS_H_

#include <stdint.h>
#include <stdbool.h>
#include "FreeRTOS.h"
#include "task.h"
#include "system/periodic_task.h"


/**
 * Variable context for the task.
 */
struct periodic_task_freertos_state {
	TaskHandle_t task;								/**< The task that will execute periodic operations. */
};

/**
 * FreeRTOS implementation for a task to handle event processing.
 */
struct periodic_task_freertos {
	struct periodic_task_freertos_state *state;		/**< Variable context for the task. */
	const struct periodic_task_handler **handlers;	/**< List of registered handlers. */
	size_t num_handlers;							/**< Number of registered handlers in the list. */
	int id;											/**< Logging identifier. */
};


int periodic_task_freertos_init (struct periodic_task_freertos *task,
	struct periodic_task_freertos_state *state, const struct periodic_task_handler **handlers,
	size_t num_handlers, int log_id);
int periodic_task_freertos_init_state (const struct periodic_task_freertos *task);
void periodic_task_freertos_release (const struct periodic_task_freertos *task);

#if configSUPPORT_DYNAMIC_ALLOCATION == 1
int periodic_task_freertos_start (const struct periodic_task_freertos *task, uint16_t stack_words,
	const char *task_name, int priority);
#endif

#if configSUPPORT_STATIC_ALLOCATION == 1
int periodic_task_freertos_start_static (const struct periodic_task_freertos *task,
	StaticTask_t *context, StackType_t *stack, uint32_t stack_words, const char *task_name,
	int priority);
#endif


#endif /* PERIODIC_TASK_FREERTOS_H_ */
