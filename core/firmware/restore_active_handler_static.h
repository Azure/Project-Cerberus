// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RESTORE_ACTIVE_HANDLER_STATIC_H_
#define RESTORE_ACTIVE_HANDLER_STATIC_H_

#include "firmware_update_handler.h"


/* Internal functions declared to allow for static initialization. */
void restore_active_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/**
 * Constant initializer for the firmware update task API.
 */
#define	RESTORE_ACTIVE_HANDLER_EVENT_API_INIT  { \
		.execute = restore_active_handler_execute, \
	}


/**
 * Initialize a static instance of a handler to restore the active firmware image in flash from
 * the recovery image.  This handler must be run from the same task context as the firmware updater.
 *
 * There is no validation done on the arguments.
 *
 * @param updater_ptr The firmware updater managing the flash containing firmware images.
 * @param task_ptr The task context for running firmware image management operations.
 */
#define	restore_active_handler_static_init(updater_ptr, task_ptr)	{ \
		.base = RESTORE_ACTIVE_HANDLER_EVENT_API_INIT, \
		.updater = updater_ptr, \
		.task = task_ptr, \
	}


#endif	/* RESTORE_ACTIVE_HANDLER_STATIC_H_ */
