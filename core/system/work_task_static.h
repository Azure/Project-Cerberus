// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_STATIC_H_
#define WORK_TASK_STATIC_H_

#include "work_task.h"


/* Internal functions declared to allow for static initialization. */
int work_task_submit (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context);
int work_task_schedule (const struct work_task_interface *task, struct work_task_entry *entry,
	const struct work_task_handler *handler, void *context, const platform_clock *next_execution);
int work_task_cancel (const struct work_task_interface *task, struct work_task_entry *entry);


/**
 * Constant initializer for the work task API.
 */
#define	WORK_TASK_API_INIT  { \
		.submit = work_task_submit, \
		.schedule = work_task_schedule, \
		.cancel = work_task_cancel, \
	}

/**
 * Initialize a static instance of a work task.  This does not initialize the task state.  This can
 * be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the work task.
 */
#define	work_task_static_init(state_ptr)	{ \
		.base = WORK_TASK_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* WORK_TASK_STATIC_H_ */
