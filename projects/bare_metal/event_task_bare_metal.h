// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EVENT_TASK_BARE_METAL_H_
#define EVENT_TASK_BARE_METAL_H_

#include <stdint.h>
#include <stdbool.h>
#include "platform_api.h"
#include "system/event_task.h"
#include "system/system.h"


/**
 * Variable context for the task.
 */
struct event_task_bare_metal_state {
	struct event_task_context context;			/**< Context for handlers to use for event processing. */
	bool notifying;								/**< Flag to indicate when an event is being triggered. */
	int running;								/**< Index of the active handler for event processing. */
};

/**
 * FreeRTOS implementation for a task to handle event processing.
 */
struct event_task_bare_metal {
	struct event_task base;						/**< Base interface to the task. */
	struct event_task_bare_metal_state *state;	/**< Variable context for the task. */
	struct system *system;						/**< The system manager. */
	const struct event_task_handler **handlers;	/**< List of registered event handlers. */
	size_t num_handlers;						/**< Number of registered handlers in the list. */
};


int event_task_bare_metal_init (struct event_task_bare_metal *task,
	struct event_task_bare_metal_state *state, struct system *system,
	const struct event_task_handler **handlers, size_t num_handlers);
int event_task_bare_metal_init_state (const struct event_task_bare_metal *task);
void event_task_bare_metal_release (const struct event_task_bare_metal *task);

int event_task_bare_metal_start (const struct event_task_bare_metal *task);


#endif /* EVENT_TASK_BARE_METAL_H_ */
