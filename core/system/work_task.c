// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "work_task.h"


/**
 * Append an entry to the tail of the queue.  The caller must hold the lock.
 *
 * @param state The queue state.
 * @param entry The entry to append.  Its next pointer is cleared.
 */
static void work_task_append (struct work_task_state *state, struct work_task_entry *entry)
{
	struct work_task_entry **link = &state->head;

	entry->next = NULL;
	while (*link != NULL) {
		link = &(*link)->next;
	}

	*link = entry;
}

/**
 * Remove an entry from the queue.  The caller must hold the lock.
 *
 * @param state The queue state.
 * @param entry The entry to remove.
 *
 * @return true if the entry was found and removed, false otherwise.
 */
static bool work_task_remove (struct work_task_state *state, struct work_task_entry *entry)
{
	struct work_task_entry **link = &state->head;

	while (*link != NULL) {
		if (*link == entry) {
			*link = entry->next;
			entry->next = NULL;

			return true;
		}

		link = &(*link)->next;
	}

	return false;
}

/**
 * Compute how long until an entry is ready to run.  The caller must hold the lock.
 *
 * @param entry The entry to evaluate.
 *
 * @return Milliseconds until the entry is ready, or 0 if it is ready now or the remaining time
 * cannot be determined.
 */
static uint32_t work_task_entry_wait_ms (const struct work_task_entry *entry)
{
	uint32_t wait = 0;

	if (entry->is_scheduled) {
		if (platform_get_timeout_remaining (&entry->next_execution, &wait) != 0) {
			wait = 0;
		}
	}

	return wait;
}

/**
 * Find the pending entry that should run next: among ready entries, the highest priority (ties
 * broken by insertion order, preserving FIFO).  If none are ready, the entry with the soonest
 * deadline is returned so the worker knows how long to wait.  The caller must hold the lock.
 *
 * @param state The queue state.
 *
 * @return The highest-priority ready entry, the earliest future entry if none is ready, or null
 * if the queue is empty.
 */
static struct work_task_entry* work_task_pick (struct work_task_state *state)
{
	struct work_task_entry *best_ready = NULL;
	struct work_task_entry *soonest = NULL;
	struct work_task_entry *cur;
	uint32_t soonest_wait = 0;

	for (cur = state->head; cur != NULL; cur = cur->next) {
		uint32_t cur_wait = work_task_entry_wait_ms (cur);

		if (cur_wait == 0) {
			/* Keep the first entry when priorities are equal to preserve FIFO order. */
			if ((best_ready == NULL) || (cur->priority > best_ready->priority)) {
				best_ready = cur;
			}
		}
		else if ((soonest == NULL) || (cur_wait < soonest_wait)) {
			soonest = cur;
			soonest_wait = cur_wait;
		}
	}

	return (best_ready != NULL) ? best_ready : soonest;
}

/**
 * Queue an entry for immediate or scheduled execution and notify the worker.
 * An entry that is already pending on any queue is rejected without changing its binding.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry Caller-owned entry storage, zero-initialized before first use.
 * @param handler The handler to invoke.
 * @param context Opaque payload for the handler.
 * @param next_execution The deadline, or null for immediate execution.
 * @param priority Execution priority.  Larger values have higher priority.
 * @param failure Error to return if the queue lock cannot be acquired.
 *
 * @return 0 if the entry was queued or an error code.
 */
static int work_task_enqueue (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context, const platform_clock *next_execution,
	uint8_t priority, int failure)
{
	const struct work_task *queue = (const struct work_task*) task;
	int status;

	if ((task == NULL) || (entry == NULL) || (handler == NULL)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}
	status = platform_mutex_lock (&queue->state->lock);
	if (status != 0) {
		return failure;
	}

	/* Check ownership before changing the handler, context, or queue linkage. */
	if (entry->owner != NULL) {
		platform_mutex_unlock (&queue->state->lock);

		return WORK_TASK_ALREADY_QUEUED;
	}

	entry->handler = handler;
	entry->context = context;
	entry->priority = priority;
	if (next_execution != NULL) {
		entry->next_execution = *next_execution;
		entry->is_scheduled = true;
	}
	else {
		entry->is_scheduled = false;
	}
	entry->owner = task;

	work_task_append (queue->state, entry);

	platform_mutex_unlock (&queue->state->lock);

	/* Notify the worker after releasing the lock.  The post result does not change enqueue status. */
	platform_semaphore_post (&queue->state->wake);

	return 0;
}

int work_task_submit (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context)
{
	return work_task_enqueue (task, entry, handler, context, NULL, 0, WORK_TASK_SUBMIT_FAILED);
}

int work_task_schedule (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context, const platform_clock *next_execution)
{
	return work_task_enqueue (task, entry, handler, context, next_execution, 0,
		WORK_TASK_SCHEDULE_FAILED);
}

int work_task_cancel (const struct work_task_interface *task, struct work_task_entry *entry)
{
	const struct work_task *queue = (const struct work_task*) task;
	int status;

	if ((task == NULL) || (entry == NULL)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	status = platform_mutex_lock (&queue->state->lock);
	if (status != 0) {
		return WORK_TASK_CANCEL_FAILED;
	}

	if (entry->owner == NULL) {
		status = WORK_TASK_NOT_QUEUED;
	}
	else if (entry->owner != task) {
		status = WORK_TASK_FOREIGN_ENTRY;
	}
	else if (!work_task_remove (queue->state, entry)) {
		status = WORK_TASK_NOT_QUEUED;
	}
	else {
		entry->owner = NULL;
		status = 0;
	}

	platform_mutex_unlock (&queue->state->lock);

	if (status == 0) {
		/* Wake the worker so it can re-evaluate the soonest deadline. */
		platform_semaphore_post (&queue->state->wake);
	}

	return status;
}

/**
 * Execute at most one ready entry in the calling thread.  If no entry is ready, wait for a queue
 * notification or deadline and return without executing a handler.  The worker must call this
 * function again to re-evaluate the queue after waiting.
 *
 * Only one worker may execute entries from a task at a time.  Handlers run without the queue
 * lock held and may submit, schedule, or cancel work.
 *
 * @param task The initialized work task to process.
 * @param max_wait_ms Maximum time to wait, in milliseconds, or WORK_TASK_WAIT_FOREVER for no
 * caller-imposed limit.  This does not limit the duration of a handler invocation.
 * @param executed Optional output indicating whether a handler ran.  Unchanged on error.
 *
 * @return 0 after processing or waiting, or an error code.  Handler status, semaphore wait errors,
 * and failure to reacquire the lock after execution are not reported.
 */
int work_task_run_next (const struct work_task *task, uint32_t max_wait_ms, bool *executed)
{
	struct work_task_entry *pick;
	uint32_t wait_ms;
	bool ran = false;
	int status;

	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	status = platform_mutex_lock (&task->state->lock);
	if (status != 0) {
		return WORK_TASK_RUN_FAILED;
	}

	pick = work_task_pick (task->state);
	if (pick == NULL) {
		platform_mutex_unlock (&task->state->lock);
		platform_semaphore_wait (&task->state->wake, max_wait_ms);
	}
	else {
		wait_ms = work_task_entry_wait_ms (pick);

		if (wait_ms == 0) {
			/* Detach before invoking the handler to allow resubmission.  Keep the running entry
			 * available for cooperative priority checks. */
			work_task_remove (task->state, pick);
			pick->owner = NULL;
			task->state->running_entry = pick;
			platform_mutex_unlock (&task->state->lock);

			pick->handler->execute (pick->handler, &task->base, pick->context);
			ran = true;

			/* Clear the running entry even if reacquiring the lock fails. */
			status = platform_mutex_lock (&task->state->lock);
			task->state->running_entry = NULL;
			if (status == 0) {
				platform_mutex_unlock (&task->state->lock);
			}
		}
		else {
			/* Bound the deadline wait.  Queue notifications may wake the worker earlier. */
			if ((max_wait_ms != WORK_TASK_WAIT_FOREVER) && (max_wait_ms < wait_ms)) {
				wait_ms = max_wait_ms;
			}

			platform_mutex_unlock (&task->state->lock);
			platform_semaphore_wait (&task->state->wake, wait_ms);
		}
	}

	if (executed != NULL) {
		*executed = ran;
	}

	return 0;
}

/**
 * Submit work for immediate execution with an explicit priority.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry Caller-owned entry storage, zero-initialized before first use and not pending.
 * @param handler The handler to invoke when the entry is selected.
 * @param context Optional context passed to the handler.
 * @param priority Execution priority.  Larger values run first; equal priorities use FIFO order.
 *
 * @return 0 if the entry was queued or an error code.
 */
int work_task_submit_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	uint8_t priority)
{
	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	return work_task_enqueue (task, entry, handler, context, NULL, priority,
		WORK_TASK_SUBMIT_FAILED);
}

/**
 * Schedule work with an explicit priority.  Priority determines execution order only among
 * entries whose deadlines have expired or that were submitted for immediate execution.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry Caller-owned entry storage, zero-initialized before first use and not pending.
 * @param handler The handler to invoke when the entry is selected.
 * @param context Optional context passed to the handler.
 * @param next_execution Deadline to copy into the entry, or null for immediate execution.
 * @param priority Execution priority.  Larger values run first; equal priorities use FIFO order.
 *
 * @return 0 if the entry was queued or an error code.
 */
int work_task_schedule_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	const platform_clock *next_execution, uint8_t priority)
{
	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	return work_task_enqueue (task, entry, handler, context, next_execution, priority,
		WORK_TASK_SCHEDULE_FAILED);
}

/**
 * Schedule work to become ready after a delay, at priority zero.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry Caller-owned entry storage, zero-initialized before first use and not pending.
 * @param handler The handler to invoke when the entry is selected.
 * @param context Optional context passed to the handler.
 * @param delay_ms Delay before the entry becomes ready, in milliseconds.  Zero makes it ready now.
 *
 * @return 0 if the entry was queued or an error code.
 */
int work_task_submit_after (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context, uint32_t delay_ms)
{
	return work_task_submit_after_with_priority (task, entry, handler, context, delay_ms, 0);
}

/**
 * Schedule work to become ready after a delay, with an explicit priority.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry Caller-owned entry storage, zero-initialized before first use and not pending.
 * @param handler The handler to invoke when the entry is selected.
 * @param context Optional context passed to the handler.
 * @param delay_ms Delay before the entry becomes ready, in milliseconds.  Zero makes it ready now.
 * @param priority Execution priority.  Larger values run first; equal priorities use FIFO order.
 *
 * @return 0 if the entry was queued or an error code, including deadline initialization failures.
 */
int work_task_submit_after_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	uint32_t delay_ms, uint8_t priority)
{
	platform_clock deadline;
	int status;

	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	status = platform_init_timeout (delay_ms, &deadline);
	if (status != 0) {
		return status;
	}

	return work_task_enqueue (task, entry, handler, context, &deadline, priority,
		WORK_TASK_SCHEDULE_FAILED);
}

/**
 * Requeue an entry for immediate execution using its existing handler, context, and priority.
 * Any previous deadline is discarded.  A running handler can use this to preserve its binding
 * when yielding, but must check that resubmission succeeds before relying on another invocation.
 *
 * @param task The interface of an initialized work_task instance.
 * @param entry A previously bound entry that is not pending on any queue.
 *
 * @return 0 if the entry was queued or an error code.
 */
int work_task_resubmit (const struct work_task_interface *task, struct work_task_entry *entry)
{
	if ((task == NULL) || (entry == NULL)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	return work_task_enqueue (task, entry, entry->handler, entry->context, NULL, entry->priority,
		WORK_TASK_SUBMIT_FAILED);
}

/**
 * Check for ready work with a strictly higher priority than the currently executing entry on
 * this queue.  Call from execute() using the task passed to that invocation.
 *
 * This does not interrupt execution.  To yield, the handler must preserve progress, successfully
 * requeue its entry, and return.  The result is advisory and may change after unlocking, causing
 * an unnecessary yield or delaying one until the next check.  It does not guarantee ownership
 * or completion.
 *
 * @param task The interface of the initialized work_task executing the handler.
 *
 * @return true if higher-priority work is ready, or false if none is ready, no handler is running,
 * the task is null, or the queue lock could not be acquired.
 */
bool work_task_preempt_pending (const struct work_task_interface *task)
{
	const struct work_task *queue = (const struct work_task*) task;
	struct work_task_entry *next;
	bool preempt = false;

	if (task == NULL) {
		return false;
	}

	if (platform_mutex_lock (&queue->state->lock) != 0) {
		return false;
	}

	if (queue->state->running_entry != NULL) {
		next = work_task_pick (queue->state);
		preempt = (next != NULL) && (work_task_entry_wait_ms (next) == 0) &&
			(next->priority > queue->state->running_entry->priority);
	}

	platform_mutex_unlock (&queue->state->lock);

	return preempt;
}

/**
 * Initialize a work task.
 *
 * @param task The work task to initialize.
 * @param state Variable context for the work task.  This must be uninitialized.
 *
 * @return 0 if the work task was initialized or an error code.
 */
int work_task_init (struct work_task *task, struct work_task_state *state)
{
	if (task == NULL) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct work_task));

	task->base.submit = work_task_submit;
	task->base.schedule = work_task_schedule;
	task->base.cancel = work_task_cancel;

	task->state = state;

	return work_task_init_state (task);
}

/**
 * Initialize only the variable state for a work task.  The rest of the instance is assumed to have
 * already been initialized.  This would generally be used with a statically initialized instance.
 *
 * @param task The instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int work_task_init_state (const struct work_task *task)
{
	int status;

	if ((task == NULL) || (task->state == NULL)) {
		return WORK_TASK_INVALID_ARGUMENT;
	}

	memset (task->state, 0, sizeof (struct work_task_state));

	status = platform_mutex_init (&task->state->lock);
	if (status != 0) {
		return WORK_TASK_INIT_FAILED;
	}

	status = platform_semaphore_init (&task->state->wake);
	if (status != 0) {
		platform_mutex_free (&task->state->lock);

		return WORK_TASK_INIT_FAILED;
	}

	return 0;
}

/**
 * Release the resources used by a work task.  Stop the worker and prevent further queue access
 * before calling this function.  Pending entries are caller-owned and are detached for reuse
 * when the queue lock is acquired; their storage is not freed.
 *
 * @param task The work task to release.  This can be null.
 */
void work_task_release (const struct work_task *task)
{
	if ((task != NULL) && (task->state != NULL)) {
		struct work_task_entry *entry;

		if (platform_mutex_lock (&task->state->lock) == 0) {
			entry = task->state->head;
			task->state->head = NULL;

			while (entry != NULL) {
				struct work_task_entry *next = entry->next;

				entry->next = NULL;
				entry->owner = NULL;
				entry = next;
			}

			platform_mutex_unlock (&task->state->lock);
		}

		platform_semaphore_free (&task->state->wake);
		platform_mutex_free (&task->state->lock);
	}
}
