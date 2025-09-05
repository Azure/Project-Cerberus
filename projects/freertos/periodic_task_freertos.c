// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "periodic_task_freertos.h"
#include "system/system_logging.h"


/**
 * Initialize a periodic handler task.  The actual FreeRTOS task will not be allocated until a call
 * to one of the task allocation functions is made.
 *
 * @param task The periodic handler task to initialize.
 * @param state Variable context for the task.  This must be uninitialized.
 * @param handlers The list of handlers that can be used with this task instance.
 * @param num_handlers The number of handlers in the list.
 * @param log_id Identifier for this task in log messages.
 *
 * @return 0 if the task was initialized or an error code
 */
int periodic_task_freertos_init (struct periodic_task_freertos *task,
	struct periodic_task_freertos_state *state, const struct periodic_task_handler *const *handlers,
	size_t num_handlers, int log_id)
{
	if (task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct periodic_task_freertos));

	task->state = state;
	task->handlers = handlers;
	task->num_handlers = num_handlers;
	task->id = log_id;

	return periodic_task_freertos_init_state (task);
}

/**
 * Initialize only the variable state for a periodic handler task.  The rest of the task instance is
 * assumed to have already been initialized.  The actual FreeRTOS task will not be allocated until a
 * call to one of the task allocation functions is made.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param task The task instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int periodic_task_freertos_init_state (const struct periodic_task_freertos *task)
{
	if ((task == NULL) || (task->state == NULL) || (task->handlers == NULL) ||
		(task->num_handlers == 0)) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	memset (task->state, 0, sizeof (struct periodic_task_freertos_state));

	return 0;
}

/**
 * Stop the periodic task and release all resources used by the task.  No handlers will be released.
 *
 * There is no synchronization done to ensure a task is only stopped when nothing is running.  A
 * released task will be stopped immediately.
 *
 * @param task The task to release.
 */
void periodic_task_freertos_release (const struct periodic_task_freertos *task)
{
	if (task) {
		vTaskDelete (task->state->task);
	}
}

/**
 * Task routine to call periodic actions for registered handlers.
 *
 * @param task The task context for processing event notifications.
 */
static void periodic_task_freertos_loop (struct periodic_task_freertos *task)
{
	int status;
	int last_error = 0;

	/* Wait for the task to be started before executing anything in the task context. */
	ulTaskNotifyTake (pdTRUE, portMAX_DELAY);

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

#if configSUPPORT_DYNAMIC_ALLOCATION == 1
/**
 * Allocate the periodic handler task using dynamic allocation of task resources.  No handlers will
 * be prepared or executed until {@link periodic_task_freertos_start} is called.
 *
 * @param task The periodic task to allocate.
 * @param stack_words The size of the task stack.  The stack size is measured in words.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int periodic_task_freertos_allocate (const struct periodic_task_freertos *task,
	uint16_t stack_words, const char *task_name, int priority)
{
	int status;

	if (task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	status = xTaskCreate ((TaskFunction_t) periodic_task_freertos_loop, task_name, stack_words,
		(void*) task, priority, &task->state->task);
	if (status != pdPASS) {
		task->state->task = NULL;
		return PERIODIC_TASK_NO_MEMORY;
	}

	return 0;
}
#endif

#if configSUPPORT_STATIC_ALLOCATION == 1
/**
 * Allocate the periodic handler task using static allocation of task resources.  No handlers will
 * be prepared or executed until {@link periodic_task_freertos_start} is called.
 *
 * @param task The periodic task to allocate.
 * @param context The statically allocated FreeRTOS context for the task.
 * @param stack A buffer to use for the task's stack.
 * @param stack_words The number of words in the stack buffer.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int periodic_task_freertos_allocate_static (const struct periodic_task_freertos *task,
	StaticTask_t *context, StackType_t *stack, uint32_t stack_words, const char *task_name,
	int priority)
{
	if (task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	task->state->task = xTaskCreateStatic ((TaskFunction_t) periodic_task_freertos_loop, task_name,
		stack_words, (void*) task, priority, stack, context);
	if (task->state->task == NULL) {
		return PERIODIC_TASK_INVALID_ARGUMENT;
	}

	return 0;
}
#endif

/**
 * Start running a periodic handler task that was previously allocated.  No handlers will be called
 * until the task has been started.
 *
 * @param task The periodic task to start.  If this is null, nothing will be done.
 */
void periodic_task_freertos_start (const struct periodic_task_freertos *task)
{
	if (task != NULL) {
		xTaskNotifyGive (task->state->task);
	}
}
