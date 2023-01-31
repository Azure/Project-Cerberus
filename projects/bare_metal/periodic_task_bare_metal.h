// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_TASK_BARE_METAL_H_
#define PERIODIC_TASK_BARE_METAL_H_

#include <stdint.h>
#include <stdbool.h>
#include "system/periodic_task.h"


/**
 * FreeRTOS implementation for a task to handle event processing.
 */
struct periodic_task_bare_metal {
	const struct periodic_task_handler **handlers;	/**< List of registered handlers. */
	size_t num_handlers;							/**< Number of registered handlers in the list. */
	int id;											/**< Logging identifier. */
};


int periodic_task_bare_metal_init (struct periodic_task_bare_metal *task,
	const struct periodic_task_handler **handlers, size_t num_handlers, int log_id);
void periodic_task_bare_metal_release (const struct periodic_task_bare_metal *task);

int periodic_task_bare_metal_start (const struct periodic_task_bare_metal *task);


#endif /* PERIODIC_TASK_BARE_METAL_H_ */
