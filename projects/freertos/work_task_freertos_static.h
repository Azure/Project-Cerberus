// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef WORK_TASK_FREERTOS_STATIC_H_
#define WORK_TASK_FREERTOS_STATIC_H_

#include "work_task_freertos.h"
#include "system/work_task_static.h"


/**
 * Initialize a static instance of a FreeRTOS work task.  The FreeRTOS task itself will still be
 * dynamically or statically allocated separately.  This does not initialize the task state.  This
 * can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the task.
 */
#define	work_task_freertos_static_init(state_ptr)	{ \
		.base = work_task_static_init (&(state_ptr)->queue), \
		.state = state_ptr, \
	}


#endif	/* WORK_TASK_FREERTOS_STATIC_H_ */
