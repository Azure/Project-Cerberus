// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_TASK_FREERTOS_STATIC_H_
#define PERIODIC_TASK_FREERTOS_STATIC_H_

#include "periodic_task_freertos.h"


/**
 * Initialize a static instance of a FreeRTOS periodic handler task.  The FreeRTOS task itself will
 * still be dynamically allocated.  This does not initialize the task state.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the task.
 * @param handlers_list The list of event handlers that can be used with this task instance.
 * @param count The number of event handlers in the list.
 * @param log_id Identifier for this task in log messages.
 */
#define	periodic_task_freertos_static_init(state_ptr, handlers_list, count, log_id)	{ \
		.state = state_ptr, \
		.handlers = handlers_list, \
		.num_handlers = count, \
		.id = log_id \
	}


#endif /* PERIODIC_TASK_FREERTOS_STATIC_H_ */
