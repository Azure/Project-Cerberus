// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "event_task_bare_metal.h"


int event_task_bare_metal_lock (const struct event_task *task)
{
	const struct event_task_bare_metal *bare_metal = (const struct event_task_bare_metal*) task;

	if (bare_metal == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	/* No need for a lock in a bare-metal environment. */
	return 0;
}

int event_task_bare_metal_unlock (const struct event_task *task)
{
	const struct event_task_bare_metal *bare_metal = (const struct event_task_bare_metal*) task;

	if (bare_metal == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	return 0;
}

int event_task_bare_metal_get_event_context (const struct event_task *task,
	struct event_task_context **context)
{
	const struct event_task_bare_metal *bare_metal = (const struct event_task_bare_metal*) task;
	int status;

	if ((bare_metal == NULL) || (context == NULL)) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (!bare_metal->state->notifying) {
		bare_metal->state->notifying = true;
		*context = &bare_metal->state->context;
		status = 0;
	}
	else {
		status = EVENT_TASK_BUSY;
	}

	return status;
}

/**
 * Task routine to handle notifications for registered handlers.
 *
 * @param task The task to process event notifications.
 */
static void event_task_bare_metal_process_notification (const struct event_task_bare_metal *task)
{
	bool reset = false;

	/* Sanity check the handler index before using it. */
	if ((task->state->running >= 0) && ((size_t) task->state->running < task->num_handlers)) {
		/* Execute the selected handler for the event. */
		task->handlers[task->state->running]->execute (task->handlers[task->state->running],
			&task->state->context, &reset);
	}

	if (reset) {
		/* If the event requires it, reset the system.  We need to wait a bit before triggering
		 * the reset to allow time for any execution status to be reported. */
		platform_msleep (5000);
		system_reset (task->system);
		reset = false;	/* We should never get here, but clear the flag if the reset fails. */
	}

	task->state->running = -1;
}

int event_task_bare_metal_notify (const struct event_task *task,
	const struct event_task_handler *handler)
{
	const struct event_task_bare_metal *bare_metal = (const struct event_task_bare_metal*) task;
	int status;

	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (bare_metal->state->notifying) {
		/* Make sure the requested handler is registered with the task. */
		status = event_task_find_handler (handler, bare_metal->handlers, bare_metal->num_handlers);
		if (!ROT_IS_ERROR (status)) {
			bare_metal->state->running = status;
			status = 0;
		}

		bare_metal->state->notifying = false;
		if (status == 0) {
			/* If the handler is valid, handle the notification.  Since there is no task, just
			 * process the notification directly. */
			event_task_bare_metal_process_notification (bare_metal);
		}
	}
	else {
		status = EVENT_TASK_NOT_READY;
	}

	return status;
}

/**
 * Initialize an event handler task.
 *
 * @param task The event handler task to initialize.
 * @param state Variable context for the task.  This must be uninitialized.
 * @param system The manager for system operations.
 * @param handlers The list of event handlers that can be used with this task instance.
 * @param num_handlers The number of event handlers in the list.
 *
 * @return 0 if the task was initialized or an error code
 */
int event_task_bare_metal_init (struct event_task_bare_metal *task,
	struct event_task_bare_metal_state *state, struct system *system,
	const struct event_task_handler **handlers, size_t num_handlers)
{
	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct event_task_bare_metal));

	task->base.lock = event_task_bare_metal_lock;
	task->base.unlock = event_task_bare_metal_unlock;
	task->base.get_event_context = event_task_bare_metal_get_event_context;
	task->base.notify = event_task_bare_metal_notify;

	task->state = state;
	task->system = system;
	task->handlers = handlers;
	task->num_handlers = num_handlers;

	return event_task_bare_metal_init_state (task);
}

/**
 * Initialize only the variable state for an event handler task.  The rest of the task instance is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param task The task instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int event_task_bare_metal_init_state (const struct event_task_bare_metal *task)
{
	if ((task == NULL) || (task->state == NULL) || (task->system == NULL) ||
		(task->handlers == NULL) || (task->num_handlers == 0)) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	memset (task->state, 0, sizeof (struct event_task_bare_metal_state));

	return 0;
}

/**
 * Release the event task resources.  No handlers will be released.
 *
 * @param task The task to release.
 */
void event_task_bare_metal_release (const struct event_task_bare_metal *task)
{
	UNUSED (task);
}

/**
 * Prepare the events handler for execution.
 *
 * @param task The event task to start.
 *
 * @return 0 if the task was started or an error code.
 */
int event_task_bare_metal_start (const struct event_task_bare_metal *task)
{
	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	event_task_prepare_handlers (task->handlers, task->num_handlers);

	return 0;
}
