// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PERIODIC_TASK_BARE_METAL_STATIC_H_
#define PERIODIC_TASK_BARE_METAL_STATIC_H_

#include "periodic_task_bare_metal.h"


/**
 * Initialize a static instance of a bare-metal periodic handler task.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param handlers_list The list of event handlers that can be used with this task instance.
 * @param count The number of event handlers in the list.
 * @param log_id Identifier for this task in log messages.
 */
#define	periodic_task_bare_metal_static_init(handlers_list, count, log_id)	{ \
		.handlers = handlers_list, \
		.num_handlers = (count), \
		.id = log_id \
	}


#endif /* PERIODIC_TASK_BARE_METAL_STATIC_H_ */
