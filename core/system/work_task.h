// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_H_
#define WORK_TASK_H_

#include "work_task_interface.h"


/**
 * Variable context for a work_task.  Caller-provided storage; all fields are managed by the
 * implementation.
 */
struct work_task_state {
	struct work_task_entry *head;			/**< Intrusive list of pending entries, in insertion order. */
	platform_mutex lock;					/**< Guards the queue. */
	platform_semaphore wake;				/**< Signaled when the worker should re-evaluate the queue. */
	struct work_task_entry *running_entry;	/**< Entry currently executing, or null. */
};

/**
 * Portable work task implementation backed by an intrusive entry list.  An OS-specific backend
 * owns a worker thread that repeatedly calls work_task_run_next.
 */
struct work_task {
	struct work_task_interface base;	/**< Base work task interface. */
	struct work_task_state *state;		/**< Variable context for the task. */
};


int work_task_init (struct work_task *task, struct work_task_state *state);
int work_task_init_state (const struct work_task *task);

/** Release queue resources and detach pending caller-owned entries.  No worker may be running. */
void work_task_release (const struct work_task *task);

/** Process at most one ready entry, blocking for no more than max_wait_ms. */
int work_task_run_next (const struct work_task *task, uint32_t max_wait_ms, bool *executed);

#define	WORK_TASK_WAIT_FOREVER		0

int work_task_submit_after (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context, uint32_t delay_ms);
int work_task_submit_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	uint8_t priority);
int work_task_schedule_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	const platform_clock *next_execution, uint8_t priority);
int work_task_submit_after_with_priority (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	uint32_t delay_ms, uint8_t priority);
int work_task_resubmit (const struct work_task_interface *task, struct work_task_entry *entry);
bool work_task_preempt_pending (const struct work_task_interface *task);


#endif	/* WORK_TASK_H_ */
