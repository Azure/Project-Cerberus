// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "event_task.h"


/**
 * Prepare a list of event handlers for execution.
 *
 * @param handlers The list of handlers to prepare.  Each entry in the list is a pointer to an event
 * handler.
 * @param count The number of event handlers in the list.
 */
void event_task_prepare_handlers (const struct event_task_handler *const *handlers, size_t count)
{
	if (handlers) {
		size_t i;

		for (i = 0; i < count; i++) {
			if (handlers[i] && handlers[i]->prepare) {
				handlers[i]->prepare (handlers[i]);
			}
		}
	}
}

/**
 * Find an event handler within a list of registered handlers.
 *
 * @param handler The handler to find in the list.
 * @param list The list of event handlers known to the task.
 * @param count The number of event handlers in the list.
 *
 * @return The index in the list where the specified handler was found or an error code.  If the
 * handler is not in the list, EVENT_TASK_UNKNOWN_HANDLER will be returned.  Use ROT_IS_ERROR to
 * check the return value.
 */
int event_task_find_handler (const struct event_task_handler *handler,
	const struct event_task_handler *const *list, size_t count)
{
	size_t i;

	if (list == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (handler != NULL) {
		for (i = 0; i < count; i++) {
			if (list[i] == handler) {
				return i;
			}
		}
	}

	return EVENT_TASK_UNKNOWN_HANDLER;
}

/**
 * Notify the task that an event needs to be processed.
 *
 * @param task The task that needs to be notified.
 * @param handler The handler that has received the event.
 * @param action The firmware update action that needs to be performed.
 * @param data Data associated with the update event.  Null if there is no data.
 * @param length Length of the event data.  This will be ignored if there is no data.
 * @param starting_status Event status to report when the task is ready to receive a notification.
 * @param status_out Optional output for starting status reporting.
 *
 * @return 0 if the update task was notified successfully or an error code.
 */
int event_task_submit_event (const struct event_task *task,
	const struct event_task_handler *handler, uint32_t action, const uint8_t *data, size_t length,
	int starting_status, int *status_out)
{
	struct event_task_context *context;
	int status;

	if ((task == NULL) || (handler == NULL)) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (length > EVENT_TASK_CONTEXT_BUFFER_LENGTH) {
		return EVENT_TASK_TOO_MUCH_DATA;
	}

	status = task->get_event_context (task, &context);
	if (status == 0) {
		/* The context was successfully acquired.  Indicate that notification has started. */
		if (status_out) {
			*status_out = starting_status;
		}

		context->action = action;
		if (data != NULL) {
			context->buffer_length = length;
			memcpy (context->event_buffer, data, length);
		}
		else {
			context->buffer_length = 0;
		}

		status = task->notify (task, handler);
	}

	return status;
}
