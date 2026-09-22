// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "work_task_freertos.h"


/**
 * Initialize a FreeRTOS work task.  The actual FreeRTOS task will not be allocated until a call to
 * one of the task allocation functions is made.
 *
 * @param task The work task to initialize.
 * @param state Variable context for the task.  This must be uninitialized.
 *
 * @return 0 if the task was initialized or an error code.
 */
int work_task_freertos_init (struct work_task_freertos *task,
	struct work_task_freertos_state *state)
{
	int status;

	if ((task == NULL) || (state == NULL)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct work_task_freertos));

	task->state = state;

	/* Initialize the portable work task. */
	status = work_task_init (&task->base, &state->queue);
	if (status != 0) {
		return status;
	}

	task->state->task = NULL;

	return 0;
}

/**
 * Initialize only the variable state for a FreeRTOS work task.  The rest of the task instance is
 * assumed to have already been initialized.  The actual FreeRTOS task will not be allocated until a
 * call to one of the task allocation functions is made.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param task The task instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int work_task_freertos_init_state (const struct work_task_freertos *task)
{
	if ((task == NULL) || (task->state == NULL) || (task->base.state != &task->state->queue)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	task->state->task = NULL;

	/* Initialize the core task state. */
	return work_task_init_state (&task->base);
}

/**
 * Stop the work task and release all resources used by the task.  Pending caller-owned entries are
 * detached so they can be reused.
 *
 * There is no synchronization done to ensure a task is only stopped when nothing is running.  A
 * released task will be stopped immediately.
 *
 * @param task The task to release.
 */
void work_task_freertos_release (const struct work_task_freertos *task)
{
	if (task != NULL) {
		if ((task->state != NULL) && (task->state->task != NULL)) {
			vTaskDelete (task->state->task);
		}

		work_task_release (&task->base);
	}
}

/**
 * Task routine that services the work queue.
 *
 * @param task The task context to run.
 */
static void work_task_freertos_loop (const struct work_task_freertos *task)
{
	/* Wait for the task to be started before processing the queue. */
	ulTaskNotifyTake (pdTRUE, portMAX_DELAY);

	while (1) {
		/* Block until the soonest entry is ready (or a submit/schedule/cancel wakes us), then run
		 * at most one entry.  All queue logic and the timed wait live in the portable core. */
		work_task_run_next (&task->base, WORK_TASK_WAIT_FOREVER, NULL);
	}
}

#if configSUPPORT_DYNAMIC_ALLOCATION == 1
/**
 * Allocate the work task using dynamic allocation of task resources.  The task will not service the
 * queue until {@link work_task_freertos_start} is called.
 *
 * @param task The work task to allocate.
 * @param stack_words The size of the task stack.  The stack size is measured in words.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int work_task_freertos_allocate (const struct work_task_freertos *task, uint16_t stack_words,
	const char *task_name, int priority)
{
	int status;

	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	status = xTaskCreate ((TaskFunction_t) work_task_freertos_loop, task_name, stack_words,
		(void*) task, priority, &task->state->task);
	if (status != pdPASS) {
		task->state->task = NULL;

		return WORK_TASK_NO_MEMORY;
	}

	return 0;
}
#endif

#if configSUPPORT_STATIC_ALLOCATION == 1
/**
 * Allocate the work task using static allocation of task resources.  The task will not service the
 * queue until {@link work_task_freertos_start} is called.
 *
 * @param task The work task to allocate.
 * @param context The statically allocated FreeRTOS context for the task.
 * @param stack A buffer to use for the task's stack.
 * @param stack_words The number of words in the stack buffer.
 * @param task_name An identifying name to assign to the task.  The maximum length is determined by
 * the FreeRTOS configuration for the platform.
 * @param priority The priority to assign to this task.
 *
 * @return 0 if the task was allocated or an error code.
 */
int work_task_freertos_allocate_static (const struct work_task_freertos *task,
	StaticTask_t *context, StackType_t *stack, uint32_t stack_words, const char *task_name,
	int priority)
{
	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	task->state->task = xTaskCreateStatic ((TaskFunction_t) work_task_freertos_loop, task_name,
		stack_words, (void*) task, priority, stack, context);
	if (task->state->task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	return 0;
}
#endif

/**
 * Start running a work task that was previously allocated.  The queue will not be serviced until
 * the task has been started.
 *
 * @param task The work task to start.  If this is null, nothing will be done.
 */
void work_task_freertos_start (const struct work_task_freertos *task)
{
	if (task != NULL) {
		xTaskNotifyGive (task->state->task);
	}
}
