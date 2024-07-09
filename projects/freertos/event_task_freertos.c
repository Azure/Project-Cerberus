// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "event_task_freertos.h"


int event_task_freertos_lock (const struct event_task *task)
{
	const struct event_task_freertos *freertos = (const struct event_task_freertos*) task;

	if (freertos == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	return platform_mutex_lock (&freertos->state->lock);
}

int event_task_freertos_unlock (const struct event_task *task)
{
	const struct event_task_freertos *freertos = (const struct event_task_freertos*) task;

	if (freertos == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	return platform_mutex_unlock (&freertos->state->lock);
}

int event_task_freertos_get_event_context (const struct event_task *task,
	struct event_task_context **context)
{
	const struct event_task_freertos *freertos = (const struct event_task_freertos*) task;
	int status;

	if ((freertos == NULL) || (context == NULL)) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (freertos->state->task) {
		platform_mutex_lock (&freertos->state->lock);
		if (!freertos->state->notifying && (freertos->state->running < 0)) {
			freertos->state->notifying = true;
			*context = &freertos->state->context;
			status = 0;
		}
		else {
			platform_mutex_unlock (&freertos->state->lock);
			status = EVENT_TASK_BUSY;
		}
	}
	else {
		status = EVENT_TASK_NO_TASK;
	}

	return status;
}

int event_task_freertos_notify (const struct event_task *task,
	const struct event_task_handler *handler)
{
	const struct event_task_freertos *freertos = (const struct event_task_freertos*) task;
	int status;

	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	if (freertos->state->task) {
		if (freertos->state->running < 0) {
			if (freertos->state->notifying) {
				/* Make sure the requested handler is registered with the task. */
				status = event_task_find_handler (handler, freertos->handlers,
					freertos->num_handlers);
				if (!ROT_IS_ERROR (status)) {
					freertos->state->running = status;
					status = 0;
				}

				freertos->state->notifying = false;
				platform_mutex_unlock (&freertos->state->lock);
				if (freertos->state->running >= 0) {
					/* If the handler is valid, notify the task to process the event. */
					xTaskNotifyGive (freertos->state->task);
				}
			}
			else {
				status = EVENT_TASK_NOT_READY;
			}
		}
		else {
			status = EVENT_TASK_BUSY;
		}
	}
	else {
		status = EVENT_TASK_NO_TASK;
	}

	return status;
}

/**
 * Initialize an event handler task.  The actual FreeRTOS task will not be allocated until a call to
 * one of the task allocation functions is made.
 *
 * @param task The event handler task to initialize.
 * @param state Variable context for the task.  This must be uninitialized.
 * @param system The manager for system operations.
 * @param handlers The list of event handlers that can be used with this task instance.
 * @param num_handlers The number of event handlers in the list.
 *
 * @return 0 if the task was initialized or an error code
 */
int event_task_freertos_init (struct event_task_freertos *task,
	struct event_task_freertos_state *state, struct system *system,
	const struct event_task_handler **handlers, size_t num_handlers)
{
	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct event_task_freertos));

	task->base.lock = event_task_freertos_lock;
	task->base.unlock = event_task_freertos_unlock;
	task->base.get_event_context = event_task_freertos_get_event_context;
	task->base.notify = event_task_freertos_notify;

	task->state = state;
	task->system = system;
	task->handlers = handlers;
	task->num_handlers = num_handlers;

	return event_task_freertos_init_state (task);
}

/**
 * Initialize only the variable state for an event handler task.  The rest of the task instance is
 * assumed to have already been initialized.  The actual FreeRTOS task will not be allocated until a
 * call to one of the task allocation functions is made.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param task The task instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int event_task_freertos_init_state (const struct event_task_freertos *task)
{
	if ((task == NULL) || (task->state == NULL) || (task->system == NULL) ||
		(task->handlers == NULL) || (task->num_handlers == 0)) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	memset (task->state, 0, sizeof (struct event_task_freertos_state));

	/* Leave the running handler set to 0 initially.  This will get cleared after the handlers have
	 * been initialized for execution within the task context. */

	return platform_mutex_init (&task->state->lock);
}

/**
 * Stop the event task and release all resources used by the task.  No handlers will be released.
 *
 * There is no synchronization done to ensure a task is only stopped when nothing is running.  A
 * released task will be stopped immediately.
 *
 * @param task The task to release.
 */
void event_task_freertos_release (const struct event_task_freertos *task)
{
	if (task) {
		vTaskDelete (task->state->task);
		platform_mutex_free (&task->state->lock);
	}
}

/**
 * Task routine to handle notifications for registered handlers.
 *
 * @param task The task to process event notifications.
 */
static void event_task_freertos_process_notification (const struct event_task_freertos *task)
{
	bool reset = false;

	/* Wait for the task to be started before executing anything in the task context. */
	ulTaskNotifyTake (pdTRUE, portMAX_DELAY);

	event_task_prepare_handlers (task->handlers, task->num_handlers);

	/* Indicate that the handlers have been initialized and the task is ready to process
	 * notifications. */
	platform_mutex_lock (&task->state->lock);
	task->state->running = -1;
	platform_mutex_unlock (&task->state->lock);

	while (1) {
		/* Wait for notification that an event should be processed. */
		ulTaskNotifyTake (pdTRUE, portMAX_DELAY);

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

		/* Clear the running handler to be ready for the next event notification. */
		platform_mutex_lock (&task->state->lock);
		task->state->running = -1;
		platform_mutex_unlock (&task->state->lock);
	}
}

#if configSUPPORT_DYNAMIC_ALLOCATION == 1
/**
 * Allocate the event handler task using dynamic allocation of task resources.  The task will not be
 * ready for processing events until {@link event_task_freertos_start} is called.
 *
 * @param task The event task to allocate.
 * @param stack_words The size of the task stack.  The stack size is measured in words.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int event_task_freertos_allocate (const struct event_task_freertos *task, uint16_t stack_words,
	const char *task_name, int priority)
{
	int status;

	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	status = xTaskCreate ((TaskFunction_t) event_task_freertos_process_notification, task_name,
		stack_words, (void*) task, priority, &task->state->task);
	if (status != pdPASS) {
		task->state->task = NULL;
		return EVENT_TASK_NO_MEMORY;
	}

	return 0;
}
#endif

#if configSUPPORT_STATIC_ALLOCATION == 1
/**
 * Allocate the event handler task using static allocation of task resources.  The task will not be
 * ready for processing events until {@link event_task_freertos_start} is called.
 *
 * @param task The event task to allocate.
 * @param context The statically allocated FreeRTOS context for the task.
 * @param stack A buffer to use for the task's stack.
 * @param stack_words The number of words in the stack buffer.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int event_task_freertos_allocate_static (const struct event_task_freertos *task,
	StaticTask_t *context, StackType_t *stack, uint32_t stack_words, const char *task_name,
	int priority)
{
	if (task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	task->state->task = xTaskCreateStatic (
		(TaskFunction_t) event_task_freertos_process_notification, task_name, stack_words,
		(void*) task, priority, stack, context);
	if (task->state->task == NULL) {
		return EVENT_TASK_INVALID_ARGUMENT;
	}

	return 0;
}
#endif

/**
 * Start running an event handler task that was previously allocated.  No events can be handled
 * until the task has been started.
 *
 * @param task The event task to start.  If this is null, nothing will be done.
 */
void event_task_freertos_start (const struct event_task_freertos *task)
{
	if (task != NULL) {
		xTaskNotifyGive (task->state->task);
	}
}
