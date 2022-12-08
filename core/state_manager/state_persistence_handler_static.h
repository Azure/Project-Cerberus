// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_PERSISTENCE_HANDLER_STATIC_H_
#define STATE_PERSISTENCE_HANDLER_STATIC_H_

#include "state_persistence_handler.h"


/* Internal functions declared to allow for static initialization. */
void state_persistence_handler_prepare (const struct periodic_task_handler *handler);
const platform_clock* state_persistence_handler_get_next_execution (
	const struct periodic_task_handler *handler);
void state_persistence_handler_execute (const struct periodic_task_handler *handler);


/**
 * Constant initializer for the log flush task API.
 */
#define	LOG_FLUSH_HANDLER_API_INIT  { \
		.prepare = state_persistence_handler_prepare, \
		.get_next_execution = state_persistence_handler_get_next_execution, \
		.execute = state_persistence_handler_execute, \
	}


/**
 * Initialize a static instance of a state persistence handler.  This does not initialize the
 * handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state Variable context for the handler.
 * @param managers_ptr The list of states that should be flushed.
 * @param num_managers The number of state managers in the list.
 * @param period_ms The amount of time between state storage requests, in milliseconds.
 */
#define	state_persistence_handler_static_init(state_ptr, managers_ptr, num_managers, period_ms)	{ \
		.base = LOG_FLUSH_HANDLER_API_INIT, \
		.state = state_ptr, \
		.managers = managers_ptr, \
		.manager_count = num_managers, \
		.period = period_ms, \
	}


#endif /* STATE_PERSISTENCE_HANDLER_STATIC_H_ */
