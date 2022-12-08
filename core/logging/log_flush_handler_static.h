// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOG_FLUSH_HANDLER_STATIC_H_
#define LOG_FLUSH_HANDLER_STATIC_H_

#include "log_flush_handler.h"


/* Internal functions declared to allow for static initialization. */
void log_flush_handler_prepare (const struct periodic_task_handler *handler);
const platform_clock* log_flush_handler_get_next_execution (
	const struct periodic_task_handler *handler);
void log_flush_handler_execute (const struct periodic_task_handler *handler);


/**
 * Constant initializer for the log flush task API.
 */
#define	LOG_FLUSH_HANDLER_API_INIT  { \
		.prepare = log_flush_handler_prepare, \
		.get_next_execution = log_flush_handler_get_next_execution, \
		.execute = log_flush_handler_execute, \
	}


/**
 * Initialize a static instance of a log flush handler.  This does not initialize the handler state.
 * This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state Variable context for the handler.
 * @param logs_ptr The list of logs that should be flushed.
 * @param num_logs The number of logs in the list.
 * @param period_ms The amount of time between log flush requests, in milliseconds.
 */
#define	log_flush_handler_static_init(state_ptr, logs_ptr, num_logs, period_ms)	{ \
		.base = LOG_FLUSH_HANDLER_API_INIT, \
		.state = state_ptr, \
		.logs = logs_ptr, \
		.log_count = num_logs, \
		.period = period_ms, \
	}


#endif /* LOG_FLUSH_HANDLER_STATIC_H_ */
