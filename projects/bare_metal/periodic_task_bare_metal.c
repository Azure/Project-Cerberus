// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "periodic_task_bare_metal.h"
#include "common/unused.h"
#include "system/system_logging.h"


/**
 * Initialize a periodic handler task.
 *
 * @param task The periodic handler task to initialize.
 * @param handlers The list of handlers that can be used with this task instance.
 * @param num_handlers The number of handlers in the list.
 * @param log_id Identifier for this task in log messages.
 *
 * @return 0 if the task was initialized or an error code
 */
int periodic_task_bare_metal_init (struct periodic_task_bare_metal *task,
	const struct periodic_task_handler **handlers, size_t num_handlers, int log_id)
{
	if (task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct periodic_task_bare_metal));

	task->handlers = handlers;
	task->num_handlers = num_handlers;
	task->id = log_id;

	return 0;
}

/**
 * Release all resources used by the task.  No handlers will be released.
 *
 * @param task The task to release.
 */
void periodic_task_bare_metal_release (const struct periodic_task_bare_metal *task)
{
	UNUSED (task);
}

/**
 * Start running the periodic handler task. No handlers will be called until the task has been
 * started.
 *
 * Execution of a task will enter an infinite loop, executing the registered handlers.  This call
 * will not return.
 *
 * @param task The periodic task to start.
 *
 * @return 0 if the task was started or an error code.
 */
int periodic_task_bare_metal_start (const struct periodic_task_bare_metal *task)
{
	int status;
	int last_error = 0;

	if (task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	periodic_task_prepare_handlers (task->handlers, task->num_handlers);

	while (1) {
		status = periodic_task_execute_next_handler (task->handlers, task->num_handlers);
		if ((status != 0) && (status != last_error)) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
				SYSTEM_LOGGING_PERIODIC_FAILED, task->id, status);
		}

		last_error = status;
	}
}
