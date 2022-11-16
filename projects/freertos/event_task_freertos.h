// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EVENT_TASK_FREERTOS_H_
#define EVENT_TASK_FREERTOS_H_

#include <stdint.h>
#include <stdbool.h>
#include "platform_api.h"
#include "system/event_task.h"
#include "system/system.h"


/**
 * Variable context for the task.
 */
struct event_task_freertos_state {
	struct event_task_context context;			/**< Context for handlers to use for event processing. */
	TaskHandle_t task;							/**< The task that will execute event handlers. */
	platform_mutex lock;						/**< Synchronization with the execution task. */
	bool notifying;								/**< Flag to indicate when an event is being triggered. */
	int running;								/**< Index of the active handler for event processing. */
};

/**
 * FreeRTOS implementation for a task to handle event processing.
 */
struct event_task_freertos {
	struct event_task base;						/**< Base interface to the task. */
	struct event_task_freertos_state *state;	/**< Variable context for the task. */
	struct system *system;						/**< The system manager. */
	const struct event_task_handler **handlers;	/**< List of registered event handlers. */
	size_t num_handlers;						/**< Number of registered handlers in the list. */
};


int event_task_freertos_init (struct event_task_freertos *task,
	struct event_task_freertos_state *state, struct system *system,
	const struct event_task_handler **handlers, size_t num_handlers);
int event_task_freertos_init_state (const struct event_task_freertos *task);
void event_task_freertos_release (const struct event_task_freertos *task);

int event_task_freertos_start (const struct event_task_freertos *task, uint16_t stack_words,
	const char *task_name, int priority);


#endif /* EVENT_TASK_FREERTOS_H_ */
